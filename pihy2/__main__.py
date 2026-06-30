"""pihy2 命令行入口： python3 -m pihy2 <命令>

  install / wizard   交互式一键部署向导
  web                启动 WebUI 管理面板（--port / --bind）
  apply              重新生成并应用配置（校验 + 重启 mihomo）
  status             查看服务状态与当前出口 IP
  restart/start/stop 控制 mihomo 服务
  config             打印将会生成的 mihomo 配置
  add                从链接快速添加节点并应用（--apply）
  selftest           运行期健康自检（安装/服务/配置/出口是否正常）
  restore-defaults   把设置恢复出厂默认（不动节点/订阅/规则/面板密码）
  uninstall          卸载（--purge 同时删除二进制与配置）
  version            版本
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, manager, config_gen
from .store import Store, state_lock


def cmd_install(args):
    from .wizard import run_wizard
    run_wizard()


def cmd_web(args):
    from .webui import serve
    serve(port=args.port, bind=args.bind)


def cmd_apply(args):
    with state_lock():                       # 与 WebUI/订阅定时更新互斥，读到一致快照
        store = Store()
        ok, msg = manager.apply_config(store, restart=not args.no_restart)
    print(msg)
    sys.exit(0 if ok else 1)


def cmd_status(args):
    st = manager.service_status("mihomo")
    web = manager.service_status("pihy2-web")
    print(f"mihomo   : {st['active']} / 开机自启 {st['enabled']}")
    print(f"pihy2-web: {web['active']} / 开机自启 {web['enabled']}")
    store = Store()
    print(f"节点数   : {len(store.data['nodes'])}  当前: "
          f"{(store.active_node() or {}).get('name', '无')}")
    if args.ip:
        print(f"出口 IP  : {manager.current_ip(timeout=6, retries=2)}")  # 限定重试/超时，避免出口失败时阻塞太久
    print("\n最近日志：")
    print(manager.journal("mihomo", 15))


def cmd_service(args):
    manager.service_action("mihomo", args.action)
    print(f"已对 mihomo 执行 {args.action}")


def cmd_config(args):
    store = Store()
    cfg = store.render_config()
    # 默认脱敏节点密码/UUID/混淆密码与 clash 密钥（与 WebUI 的 /api/config 一致），
    # 避免 `pihy2 config | tee` 等把凭据泄露到日志/滚屏。--with-secrets 显示全部明文。
    if not getattr(args, "with_secrets", False):
        cfg = config_gen.redact_secrets(cfg)
    print(cfg)


def cmd_add(args):
    from . import parser
    text = args.link or sys.stdin.read()
    nodes, errs = parser.parse_many(text)
    for e in errs:
        print("  " + e)
    if not nodes:
        print("没有解析到节点")
        sys.exit(1)
    with state_lock():
        store = Store()
        added = store.add_nodes(nodes)
        store.save()
        for n in added:
            print(f"已添加：{n['name']}  {n['server']}:{n['port']}")
        if args.apply:
            ok, msg = manager.apply_config(store)
            print(msg)
            if not ok:                       # 应用失败要反映到退出码，便于脚本/CI 感知（CLI-3）
                sys.exit(1)


def cmd_uninstall(args):
    manager.uninstall(purge=args.purge)


def cmd_selftest(args):
    result = manager.self_test(Store(), probe_ip=not args.quick)
    sym = {"ok": "✓", "warn": "!", "fail": "✗", "skip": "–"}
    for c in result["checks"]:
        line = f"  {sym.get(c['status'], '?')} {c['label']}"
        if c["detail"]:
            line += f"：{c['detail']}"
        print(line)
    s = result["summary"]
    print(f"\n自检完成：通过 {s['ok']} / 警告 {s['warn']} / 失败 {s['fail']} / 跳过 {s['skip']}")
    sys.exit(0 if result["ok"] else 1)   # 有失败项即非零退出，便于脚本/CI 感知


def cmd_restore_defaults(args):
    with state_lock():                   # 与面板/订阅定时器互斥，避免半写状态
        store = Store()
        store.restore_default_settings()
        store.save()
    print("已把设置恢复为出厂默认（保留节点 / 订阅 / 路由规则 / 面板密码 / clash 密钥）。")
    if args.apply:
        ok, msg = manager.apply_config(Store())   # 慢 IO 放锁外
        print(msg)
        if not ok:
            sys.exit(1)
    else:
        print("提示：运行 `pihy2 apply` 或在面板点“应用配置并重启”后生效。")


def cmd_sub(args):
    action = args.sub_action
    if action == "list":
        store = Store()
        subs = store.data.get("subscriptions", [])
        if not subs:
            print("（无订阅）")
        for s in subs:
            print(f"  {s['id']}  {s['name']}  节点{s['count']}  更新于 {s['updated'] or '从未'}\n      {s['url']}")
        return
    # 与 webui 一致：网络抓取/apply 等慢 IO 放锁外，state_lock 只罩内存读改写+存盘，
    # 避免订阅定时器在锁内做长时间抓取而阻塞面板（跨进程 fcntl 锁）。
    _cmd_sub_mutate(args, action)


def _apply_outside_lock() -> bool:
    ok, msg = manager.apply_config(Store())
    print(msg)
    return ok


def _cmd_sub_mutate(args, action):
    if action == "add":
        nodes, errs = manager.fetch_sub_nodes(args.url) if args.url else ([], ["缺少订阅 URL"])
        with state_lock():
            store = Store()
            sub = store.add_subscription(args.name or "订阅", args.url)
            cnt = store.set_subscription_nodes(sub["id"], nodes) if nodes else 0
            store.save()
        for e in errs[:3]:
            print("  " + e)
        print(f"已添加订阅 {sub['id']}（{cnt} 个节点）")
        if args.apply and not _apply_outside_lock():
            sys.exit(1)                      # 应用失败反映到退出码（CLI-3）
        return
    if action == "update":
        target = args.id or "all"
        subs = Store().data.get("subscriptions", [])     # 锁外读快照
        targets = subs if target == "all" else [s for s in subs if s["id"] == target]
        total = 0
        for s in targets:
            nodes, errs = manager.fetch_sub_nodes(s["url"])   # 锁外抓取
            if not nodes:
                for e in errs[:2]:
                    print("  " + e)
                continue
            with state_lock():                            # 锁内仅写回
                store = Store()
                if store.get_subscription(s["id"]):
                    total += store.set_subscription_nodes(s["id"], nodes)
                    store.save()
        if target == "all":
            print(f"已更新 {len(targets)} 个订阅，共 {total} 个节点")
        else:
            print(f"已更新 {total} 个节点" if targets else "订阅不存在")
        if args.apply and not _apply_outside_lock():
            sys.exit(1)                      # 应用失败反映到退出码（CLI-3）
        return
    if action == "del":
        with state_lock():
            store = Store()
            ok = store.delete_subscription(args.id, remove_nodes=not args.keep_nodes)
            store.save()
        print("已删除" if ok else "订阅不存在")
        if ok and args.apply and not _apply_outside_lock():
            sys.exit(1)                      # 应用失败反映到退出码（CLI-3）


def cmd_version(args):
    print(f"pihy2 {__version__}")


def build_parser():
    p = argparse.ArgumentParser(prog="pihy2", description="树莓派 hy2 全局代理一键部署与管理")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("install", help="交互式一键部署向导").set_defaults(func=cmd_install)
    sub.add_parser("wizard", help="同 install").set_defaults(func=cmd_install)

    w = sub.add_parser("web", help="启动 WebUI 管理面板")
    w.add_argument("--port", type=int, default=None)
    w.add_argument("--bind", default=None)
    w.set_defaults(func=cmd_web)

    a = sub.add_parser("apply", help="重新生成并应用配置")
    a.add_argument("--no-restart", action="store_true", help="只写配置不重启")
    a.set_defaults(func=cmd_apply)

    s = sub.add_parser("status", help="查看状态")
    s.add_argument("--ip", action="store_true", help="同时探测出口 IP")
    s.set_defaults(func=cmd_status)

    for act in ("restart", "start", "stop"):
        sp = sub.add_parser(act, help=f"{act} mihomo 服务")
        sp.set_defaults(func=cmd_service, action=act)

    cfgp = sub.add_parser("config", help="打印将生成的配置")
    cfgp.add_argument("--with-secrets", action="store_true", help="不脱敏（显示节点密码与 clash 密钥明文）")
    cfgp.set_defaults(func=cmd_config)

    ad = sub.add_parser("add", help="从链接添加节点")
    ad.add_argument("link", nargs="?", help="hy2 链接（省略则从标准输入读取）")
    ad.add_argument("--apply", action="store_true", help="添加后立即应用")
    ad.set_defaults(func=cmd_add)

    sb = sub.add_parser("sub", help="订阅管理")
    sbs = sb.add_subparsers(dest="sub_action", required=True)
    sbs.add_parser("list", help="列出订阅").set_defaults(func=cmd_sub)
    sba = sbs.add_parser("add", help="添加订阅")
    sba.add_argument("url"); sba.add_argument("--name", default="")
    sba.add_argument("--apply", action="store_true"); sba.set_defaults(func=cmd_sub)
    sbu = sbs.add_parser("update", help="更新订阅（id 或 all）")
    sbu.add_argument("id", nargs="?", default="all")
    sbu.add_argument("--apply", action="store_true"); sbu.set_defaults(func=cmd_sub)
    sbd = sbs.add_parser("del", help="删除订阅")
    sbd.add_argument("id"); sbd.add_argument("--keep-nodes", action="store_true")
    sbd.add_argument("--apply", action="store_true"); sbd.set_defaults(func=cmd_sub)

    stp = sub.add_parser("selftest", help="运行期健康自检")
    stp.add_argument("--quick", action="store_true", help="跳过较慢的出口 IP 探测")
    stp.set_defaults(func=cmd_selftest)

    rd = sub.add_parser("restore-defaults", help="把设置恢复出厂默认（不动节点/订阅/规则）")
    rd.add_argument("--apply", action="store_true", help="恢复后立即应用")
    rd.set_defaults(func=cmd_restore_defaults)

    un = sub.add_parser("uninstall", help="卸载")
    un.add_argument("--purge", action="store_true", help="同时删除二进制与配置")
    un.set_defaults(func=cmd_uninstall)

    sub.add_parser("version", help="版本").set_defaults(func=cmd_version)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
