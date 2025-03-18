## Auditing 的流程

1. Scoping. 先对项目有个基本的了解和统计基本的数据.
2. Recon. 从业务逻辑到代码细节, 检查代码.
3. Report. 为一个finding写报告, 主要包括标题, 描述, POC, 修改建议

## 工具: 

- cloc
- Solidity Metrics(VSCode Extension)
- 运行单个测试 `foundray test --mt test_name` 