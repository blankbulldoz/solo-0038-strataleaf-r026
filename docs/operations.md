# 恢复与观测

备份必须调用 archives.backup，不能只拷贝活动主文件。backup 与 restore 都不覆盖存在目标；恢复使用新路径，先校验来源 SHA-256，再打开新句柄。主库恢复生成新身份，副本恢复绑定来源。恢复清理原机保留点与消费者；消费方重新注册时须根据已恢复的 floor/head 判断是否需要重建。

diagnostics.inspect(deep=True) 检查 SQLite 完整性、外键、提交连续性、当前索引与文档投影；fingerprint 比较指定读视图的键、文档版本、内容及到期事实。前者不能证明所有业务数据正确，后者相同也不能代替模式与索引定义比对。checkpoint 返回 SQLite 的 busy、log、checkpointed 信息，并不承诺截断 WAL。

examples.observations 的 contention 会让独立连接暂持 IMMEDIATE 锁，记录第二句柄的 busy 超时及释放后的成功；retention_pressure 记录读保留点和消费者分别阻止水位推进的现象。它们用独立临时文件，不接触生产路径。观察包含真实修订和异常，适合复核运行边界。

关闭所有调用方句柄再移动数据目录；不支持共享网络盘或多主写入。在空间紧张时先核实 pin/消费者，推进已完成的确认后再回收；回收不自动缩小文件，物理容量由 SQLite 空闲页复用。到期清理只在显式调用时执行，不能把墙钟到期等同于读视图变动。

向外部协作方交付时使用 `transfer.export_redacted` 并保存 `manifest`：它是接收方核对“导出是否完整、规则是否一致”的非敏感材料。交付内容包括各集合的 `lines`、`manifest` 与 `key_fingerprint`，不要把 `key` 或原库一并交出。接收方可直接对 manifest 和行调用 `transfer.verify_redacted`；`ok` 为假时逐条看 `issues`（计数、摘要、覆盖率、规则摘要），这些信息不包含被删除或替换的原值。若两次交付要能对照同一批替身，用同一个 `key` 和同一 `revision`；否则令牌不可比。脱敏导出不注册保留点，导出后仍可能被回收，长时交付前先 `retention.pin`，交付完成再 `unpin`。
