import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .codec import digest, dumps, loads, name
from .errors import InvalidDocument, NotFound
from .mvcc import checked_revision, record, visible_rows
from .transaction import WriteBatch

ACTIONS = ("delete", "keep", "replace")
DIRECTIVES = ("default", "expires", "keys")
TOKEN_PREFIX = "r1_"
# Document keys and ungrouped field replacements share one namespace, so a key
# kept as a cross-collection reference can be replaced with the same group.
KEY_GROUP = "default"
KEY_FINGERPRINT_LABEL = b"strataleaf-redaction-key-v1"
GROUP_LABEL = b"strataleaf-redaction-group-v1"
TOKEN_LABEL = b"strataleaf-redaction-token-v1"
_DELETE = object()


@dataclass(frozen=True)
class Rule:
    path: str
    components: tuple
    action: str
    group: str | None


class Pseudonyms:
    """Deterministic, keyed replacement tokens for redacted scalar values."""

    def __init__(self, secret):
        self.secret = secret
        self._groups = {}
        self._tokens = {}

    def _derived(self, group):
        if group not in self._groups:
            material = hashlib.sha256(GROUP_LABEL + b"\0" + group.encode()).digest()
            self._groups[group] = hmac.new(self.secret, material, hashlib.sha256).digest()
        return self._groups[group]

    def token(self, group, value):
        canonical = dumps(value)
        identity = (group, canonical)
        token = self._tokens.get(identity)
        if token is None:
            raw = hmac.new(self._derived(group), TOKEN_LABEL + b"\0" + canonical.encode(), hashlib.sha256).digest()[:16]
            token = TOKEN_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")
            self._tokens[identity] = token
        return token


def redaction_secret(value):
    if value is None:
        return secrets.token_bytes(32)
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)) or not value:
        raise InvalidDocument("redaction key must be nonempty text or bytes")
    return bytes(value)


def key_fingerprint(secret):
    return hmac.new(secret, KEY_FINGERPRINT_LABEL, hashlib.sha256).hexdigest()[:16]


def collection_names(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)) or not value:
        raise InvalidDocument("redacted export requires at least one collection")
    names = [name(item) for item in value]
    if len(set(names)) != len(names):
        raise InvalidDocument("redacted export collections must be unique")
    return names


def rule_components(path, action):
    if not isinstance(path, str) or not path:
        raise InvalidDocument("redaction paths must be nonempty strings")
    components = tuple(path.split("."))
    if any(not component for component in components):
        raise InvalidDocument("redaction paths must have nonempty dot-separated components")
    if "*" in components:
        if action != "replace" or components[-1] != "*" or components.count("*") != 1 or len(components) < 2:
            raise InvalidDocument("the wildcard component is only allowed as the final component of a replacement path")
    return components


def rule_group(value):
    if not isinstance(value, str) or not value or len(value.encode()) > 64:
        raise InvalidDocument("redaction groups must be nonempty strings of at most 64 bytes")
    return value


def rule_entries(value):
    if isinstance(value, (str, dict)):
        return [value]
    if not isinstance(value, (list, tuple)):
        raise InvalidDocument("redaction paths must be a string, an object or an array of them")
    return list(value)


def prefix_overlap(left, right):
    shared = min(len(left), len(right))
    return all(a == b or a == "*" or b == "*" for a, b in zip(left[:shared], right[:shared]))


def collection_plan(collection, spec):
    if not isinstance(spec, dict):
        raise InvalidDocument("redaction rules for a collection must be an object")
    if set(spec) - set(ACTIONS) - set(DIRECTIVES):
        raise InvalidDocument("unknown redaction directive for collection: " + collection)
    keys = spec.get("keys", "replace")
    if keys not in ("keep", "replace"):
        raise InvalidDocument("keys directive must be keep or replace")
    expires = spec.get("expires", "keep")
    if expires not in ("keep", "delete"):
        raise InvalidDocument("expires directive must be keep or delete")
    default = spec.get("default", "keep")
    if default not in ("keep", "delete"):
        raise InvalidDocument("default directive must be keep or delete")
    rules = []
    for action in ACTIONS:
        if action not in spec:
            continue
        for entry in rule_entries(spec[action]):
            group = None
            if action == "replace":
                if isinstance(entry, dict):
                    if set(entry) not in ({"path"}, {"path", "group"}):
                        raise InvalidDocument("replacement entries accept path and optional group")
                    path = entry["path"]
                    group = rule_group(entry.get("group", "default"))
                else:
                    path = entry
                    group = "default"
            else:
                if isinstance(entry, dict):
                    raise InvalidDocument("delete and keep entries must be path strings")
                path = entry
            components = rule_components(path, action)
            rules.append(Rule(".".join(components), components, action, group))
    for index, rule in enumerate(rules):
        for other in rules[index + 1:]:
            if prefix_overlap(rule.components, other.components):
                raise InvalidDocument("overlapping redaction rules: " + rule.path + " and " + other.path)
    return {"rules": tuple(rules), "keys": keys, "expires": expires, "default": default}


def nested_form(names, rules):
    if len(names) != 1 or names[0] not in rules:
        return False
    return isinstance(rules[names[0]], dict)


def normalize_rules(names, rules):
    if not isinstance(rules, dict):
        raise InvalidDocument("redaction rules must be an object")
    if set(rules) <= set(ACTIONS) | set(DIRECTIVES) and not nested_form(names, rules):
        if len(names) != 1:
            raise InvalidDocument("flat redaction rules require exactly one collection")
        return {names[0]: collection_plan(names[0], rules)}
    missing = [collection for collection in names if collection not in rules]
    if missing:
        raise InvalidDocument("missing redaction rules for collection: " + missing[0])
    unexpected = sorted(set(rules) - set(names))
    if unexpected:
        raise InvalidDocument("redaction rules provided for unexpected collection: " + unexpected[0])
    return {collection: collection_plan(collection, rules[collection]) for collection in names}


def rules_document(plan):
    document = {"keys": plan["keys"], "expires": plan["expires"], "default": plan["default"]}
    for action in ACTIONS:
        entries = []
        for rule in plan["rules"]:
            if rule.action != action:
                continue
            entries.append({"group": rule.group, "path": rule.path} if action == "replace" else rule.path)
        if entries:
            document[action] = sorted(entries, key=lambda item: item["path"] if isinstance(item, dict) else item)
    return document


def covering_rule(rules, components):
    for rule in rules:
        if "*" in rule.components or len(rule.components) > len(components):
            continue
        if rule.components == components[:len(rule.components)]:
            return rule
    return None


def element_rule(rules, components):
    for rule in rules:
        if rule.components[-1] == "*" and rule.components[:-1] == components:
            return rule
    return None


def nested_rule(rules, components):
    for rule in rules:
        if len(rule.components) <= len(components):
            continue
        head = rule.components[:len(components)]
        if all(pattern == part for pattern, part in zip(head, components)):
            return True
    return False


def redact_value(value, components, plan, pseudonyms, collection, counts):
    rule = covering_rule(plan["rules"], components)
    if rule is not None:
        counts["seen"][rule.path] = counts["seen"].get(rule.path, 0) + 1
        if rule.action == "keep":
            return value
        if rule.action == "delete":
            counts["redacted"][rule.path] = counts["redacted"].get(rule.path, 0) + 1
            return _DELETE
        if isinstance(value, (dict, list)):
            raise InvalidDocument("replacement requires a scalar value under " + collection + " rule " + rule.path)
        counts["redacted"][rule.path] = counts["redacted"].get(rule.path, 0) + 1
        return pseudonyms.token(rule.group, value)
    star = element_rule(plan["rules"], components)
    if star is not None:
        if isinstance(value, list):
            elements = value
        elif isinstance(value, dict):
            elements = list(value.values())
        else:
            raise InvalidDocument("wildcard replacement requires an array or object under "
                                  + collection + " rule " + star.path)
        counts["seen"][star.path] = counts["seen"].get(star.path, 0) + 1
        for item in elements:
            if isinstance(item, (dict, list)):
                raise InvalidDocument("replacement requires scalar elements under " + collection + " rule " + star.path)
        counts["redacted"][star.path] = counts["redacted"].get(star.path, 0) + len(elements)
        replaced = [pseudonyms.token(star.group, item) for item in elements]
        if isinstance(value, dict):
            return dict(zip(value, replaced))
        return replaced
    if isinstance(value, dict):
        if not nested_rule(plan["rules"], components) and plan["default"] == "delete":
            counts["default"] += 1
            return _DELETE
        output = {}
        for key, child in value.items():
            result = redact_value(child, components + (key,), plan, pseudonyms, collection, counts)
            if result is not _DELETE:
                output[key] = result
        return output
    if isinstance(value, list):
        if not nested_rule(plan["rules"], components) and plan["default"] == "delete":
            counts["default"] += len(value)
            return _DELETE
        return [redact_value(item, components, plan, pseudonyms, collection, counts) for item in value]
    if plan["default"] == "delete":
        counts["default"] += 1
        return _DELETE
    return value


def redact_document(document, plan, pseudonyms, collection):
    counts = {"seen": {}, "redacted": {}, "default": 0}
    output = {}
    for key, value in document.items():
        result = redact_value(value, (key,), plan, pseudonyms, collection, counts)
        if result is not _DELETE:
            output[key] = result
    return output, counts


def malformed_line(lines):
    for line in lines:
        if not isinstance(line, str):
            return True
        try:
            item = loads(line)
        except (ValueError, TypeError):
            return True
        if not isinstance(item, dict) or not {"key", "document"}.issubset(item):
            return True
        if set(item) - {"key", "document", "expires_at"} or not isinstance(item["key"], str) \
                or not isinstance(item["document"], dict):
            return True
    return False


def tombstone_count(connection, collection, revision):
    return connection.execute("""SELECT COUNT(*) FROM versions v JOIN
      (SELECT key,MAX(rev) AS r FROM versions WHERE collection=? AND rev<=? GROUP BY key) latest
      ON v.collection=? AND v.key=latest.key AND v.rev=latest.r
      WHERE v.body IS NULL""", (collection, revision, collection)).fetchone()[0]


class Transfer:
    def __init__(self, store):
        self.store = store

    def export_lines(self, collection, revision=None):
        with self.store.read() as connection:
            revision = checked_revision(self.store, revision)
            if not connection.execute("SELECT 1 FROM collections WHERE name=?", (collection,)).fetchone():
                raise NotFound("unknown collection")
            output = []
            for row in visible_rows(connection, collection, revision):
                item = record(row)
                output.append(dumps({"key": item.key, "document": item.document, "expires_at": item.expires_at}))
            return {"revision": revision, "lines": output}

    def export_redacted(self, collections, rules, revision=None, key=None):
        """Export a redacted logical view of one or more collections at a fixed revision.

        ``rules`` never carries replacements chosen by the caller: values are replaced with
        keyed deterministic tokens, so equal source values stay jointly identifiable across
        collections while the original value cannot be recovered from the export.
        """
        names = collection_names(collections)
        plans = normalize_rules(names, rules)
        secret = redaction_secret(key)
        fingerprint = key_fingerprint(secret)
        pseudonyms = Pseudonyms(secret)
        with self.store.read() as connection:
            for collection in names:
                if not connection.execute("SELECT 1 FROM collections WHERE name=?", (collection,)).fetchone():
                    raise NotFound("unknown collection: " + collection)
            revision = checked_revision(self.store, revision)
            head, floor = int(self.store.get("head")), int(self.store.get("floor"))
            catalog_epoch = int(self.store.get("catalog_epoch"))
            outputs, report = {}, {}
            for collection in names:
                plan = plans[collection]
                totals = {rule.path: {"present": 0, "absent": 0, "redacted": 0} for rule in plan["rules"]}
                default_removed = 0
                records = []
                for row in visible_rows(connection, collection, revision):
                    item = record(row)
                    document, counts = redact_document(item.document, plan, pseudonyms, collection)
                    default_removed += counts["default"]
                    for rule in plan["rules"]:
                        bucket = totals[rule.path]
                        bucket["present" if rule.path in counts["seen"] else "absent"] += 1
                        bucket["redacted"] += counts["redacted"].get(rule.path, 0)
                    out_key = (pseudonyms.token(KEY_GROUP, item.key) if plan["keys"] == "replace"
                               else item.key)
                    payload = {"key": out_key, "document": document}
                    if plan["expires"] == "keep":
                        payload["expires_at"] = item.expires_at
                    records.append(payload)
                records.sort(key=lambda item: item["key"])
                lines = [dumps(item) for item in records]
                catalog_row = connection.execute("SELECT schema,generation FROM collections WHERE name=?",
                                                 (collection,)).fetchone()
                outputs[collection] = lines
                report[collection] = {
                    "schema": loads(catalog_row["schema"]),
                    "generation": catalog_row["generation"],
                    "documents": len(lines),
                    "tombstones": tombstone_count(connection, collection, revision),
                    "sha256": digest(lines),
                    "keys": plan["keys"],
                    "expires": plan["expires"],
                    "default": plan["default"],
                    "fields_removed_by_default": default_removed,
                    "coverage": [{"path": rule.path, "action": rule.action, "group": rule.group,
                                  "documents_present": totals[rule.path]["present"],
                                  "documents_absent": totals[rule.path]["absent"],
                                  "values_redacted": totals[rule.path]["redacted"]}
                                 for rule in sorted(plan["rules"], key=lambda item: (item.path, item.action))],
                }
        rules_doc = {collection: rules_document(plans[collection]) for collection in sorted(names)}
        manifest = {
            "format": 1,
            "kind": "redacted-logical-export",
            "revision": revision,
            "head": head,
            "floor": floor,
            "catalog_epoch": catalog_epoch,
            "total_documents": sum(report[collection]["documents"] for collection in names),
            "collections": {collection: report[collection] for collection in names},
            "rules": rules_doc,
            "rules_sha256": digest(rules_doc),
            "key_fingerprint": fingerprint,
            "replacement": {"scheme": "hmac-sha256-truncated-128", "token_prefix": TOKEN_PREFIX},
            "content_sha256": digest({"format": 1, "revision": revision,
                                      "collections": {collection: outputs[collection] for collection in sorted(names)}}),
        }
        result = {"revision": revision, "key_fingerprint": fingerprint,
                  "collections": {collection: {"lines": outputs[collection], "count": len(outputs[collection])}
                                  for collection in names},
                  "manifest": manifest}
        if len(names) == 1:
            result["lines"] = outputs[names[0]]
        return result

    @staticmethod
    def verify_redacted(result):
        if not isinstance(result, dict):
            raise InvalidDocument("redacted export must be an object")
        issues = []
        manifest = result.get("manifest")
        if not isinstance(manifest, dict) or manifest.get("format") != 1 or manifest.get("kind") != "redacted-logical-export":
            raise InvalidDocument("redacted export requires a format 1 manifest")
        revision = manifest.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise InvalidDocument("manifest revision must be a nonnegative integer")
        collections = result.get("collections")
        if not isinstance(collections, dict) or not collections:
            raise InvalidDocument("redacted export requires per-collection lines")
        reported = manifest.get("collections")
        if not isinstance(reported, dict) or set(reported) != set(collections):
            issues.append("manifest collections do not match the exported collections")
        top_level = result.get("lines")
        if len(collections) == 1 and top_level is not None:
            only = next(iter(collections.values()))
            if not isinstance(only, dict) or top_level != only.get("lines"):
                issues.append("top-level lines differ from the exported collection lines")
        total = 0
        content = {}
        for collection in sorted(collections):
            entry = collections[collection]
            if not isinstance(entry, dict) or not isinstance(entry.get("lines"), list):
                issues.append("collection is missing exported lines: " + collection)
                continue
            lines = entry["lines"]
            total += len(lines)
            content[collection] = lines
            if entry.get("count") != len(lines):
                issues.append("collection document count differs from line count: " + collection)
            facts = reported.get(collection) if isinstance(reported, dict) else None
            if not isinstance(facts, dict):
                issues.append("collection is missing from the manifest: " + collection)
                continue
            if facts.get("documents") != len(lines):
                issues.append("manifest document count differs from exported lines: " + collection)
            if facts.get("sha256") != digest(lines):
                issues.append("collection content digest differs from the manifest: " + collection)
            if not isinstance(facts.get("schema"), dict) or not isinstance(facts.get("generation"), int):
                issues.append("manifest lacks schema facts for collection: " + collection)
            coverage = facts.get("coverage")
            if not isinstance(coverage, list):
                issues.append("manifest lacks redaction coverage for collection: " + collection)
            if facts.get("keys") not in ("keep", "replace") or facts.get("expires") not in ("keep", "delete") \
                    or facts.get("default") not in ("keep", "delete"):
                issues.append("manifest has invalid redaction directives for collection: " + collection)
            elif malformed_line(lines):
                issues.append("exported lines are not key/document records: " + collection)
            else:
                for item in coverage:
                    if not isinstance(item, dict) or item.get("action") not in ACTIONS:
                        issues.append("coverage entry has an unknown action: " + collection)
                        break
                    if not isinstance(item.get("path"), str) or not item["path"]:
                        issues.append("coverage entry has no path: " + collection)
                        break
                    if item.get("documents_present", 0) + item.get("documents_absent", 0) != len(lines):
                        issues.append("coverage does not account for every document: " + collection)
                        break
        rules_doc = manifest.get("rules")
        if not isinstance(rules_doc, dict) or set(rules_doc) != set(collections):
            issues.append("manifest rules do not match the exported collections")
        elif manifest.get("rules_sha256") != digest(rules_doc):
            issues.append("manifest rules digest does not match the published rules")
        if manifest.get("total_documents") != total:
            issues.append("manifest total document count differs from exported lines")
        if manifest.get("content_sha256") != digest({"format": 1, "revision": revision, "collections": content}):
            issues.append("export content digest differs from the manifest")
        if not isinstance(manifest.get("key_fingerprint"), str) or not manifest["key_fingerprint"]:
            issues.append("manifest has no replacement key fingerprint")
        elif result.get("key_fingerprint") != manifest["key_fingerprint"]:
            issues.append("top-level key fingerprint differs from the manifest")
        if result.get("revision") != revision:
            issues.append("top-level revision differs from the manifest")
        return {"ok": not issues, "issues": issues, "revision": revision,
                "documents": total, "collections": sorted(collections)}

    def import_lines(self, collection, lines, replace=False, request_key=None):
        if not isinstance(replace, bool):
            raise InvalidDocument("replace must be a boolean")
        batch = WriteBatch(self.store, request_key)
        count = 0
        for line in lines:
            count += 1
            if count > 10000 or not isinstance(line, str) or len(line.encode()) > 2 * 1024 * 1024:
                raise InvalidDocument("import exceeds bounded batch/line size")
            try:
                item = loads(line)
            except (ValueError, TypeError) as exc:
                raise InvalidDocument("invalid JSON at input line " + str(count)) from exc
            if not isinstance(item, dict) or set(item) - {"key", "document", "expires_at"} or not {"key", "document"}.issubset(item):
                raise InvalidDocument("line requires key and document, optional expires_at")
            batch.put(collection, item["key"], item["document"], expected=None if replace else 0,
                      expires_at=item.get("expires_at"))
        return batch.commit()
