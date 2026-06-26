"""pihy2 —— 树莓派 hy2(hysteria2)全局代理一键部署与管理工具。

模块划分：
    parser      节点分享链接解析（hysteria2:// / hy2:// / base64 订阅）
    config_gen  由节点 + 路由规则 + 设置生成 mihomo config.yaml
    store       状态持久化（节点 / 规则 / 设置，存于 /etc/pihy2/state.json）
    manager     系统操作（安装/卸载 mihomo、systemd、下载、应用配置、状态）
    wizard      交互式命令行向导（首次一键部署）
    webui       可视化管理面板（HTTP 服务 + REST API + clash API 代理）
"""

__version__ = "1.0"
