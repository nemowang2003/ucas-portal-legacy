# UCAS Portal

中国科学院大学 (UCAS) 校园网 Portal 认证命令行工具。

## 功能

- 支持校园网 Portal 登录
- 支持校园网 Portal 登出
- 命令行交互界面
- 支持环境变量配置账号

## 安装

```bash
uv tool install "git+ssh://git@github.com/nemowang2003/ucas-portal"
```

## 使用方法

### 基本用法

```bash
# 使用命令行参数
ucas-portal --username 你的学号 --password 你的密码

# 或使用环境变量
export UCAS_USERNAME=你的学号
export UCAS_PASSWORD=你的密码
ucas-portal
```

## 致谢

本项目基于 [szu_srun_client](https://github.com/Caterpie771881/szu_srun_client) 修改而来，感谢原始作者的贡献。
