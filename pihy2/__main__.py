"""pihy2 命令行入口： python3 -m pihy2 <命令>

  install / wizard   交互式一键部署向导
  web                启动 WebUI 管理面板（--port / --bind）
  apply              重新生成并应用配置（校验 + 重启 mihomo）
  status             查看服务状态与当前出口 IP
  restart/start/stop 控制 mihomo 服务
  config             打印将会生成的 mihomo 配置
  add                从链接快速添加节点并应用（--apply）
  uninstall          卸载（--purge 同时删除二进制与配置）
  version            版本
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, manager
from .store import Store


def cmd_install(args):
    from .wizard import run_wizard
    run_wizard()


def cmd_web(args):
    from .webui import serve
    serve(port=args.port, bind=args.bind)


def cmd_apply(args):
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
        print(f"出口 IP  : {manager.current_ip()}")
    print("\n最近日志：")
    print(manager.journal("mihomo", 15))


def cmd_service(args):
    manager.service_action("mihomo", args.action)
    print(f"已对 mihomo 执行 {args.action}")


def cmd_config(args):
    print(Store().render_config())


def cmd_add(args):
    from . import parser
    text = args.link or sys.stdin.read()
    nodes, errs = parser.parse_many(text)
    for e in errs:
        print("  " + e)
    if not nodes:
        print("没有解析到节点")
        sys.exit(1)
    store = Store()
    added = store.add_nodes(nodes)
    store.save()
    for n in added:
        print(f"已添加：{n['name']}  {n['server']}:{n['port']}")
    if args.apply:
        ok, msg = manager.apply_config(store)
        print(msg)


def cmd_uninstall(args):
    manager.uninstall(purge=args.purge)


def cmd_sub(args):
    store = Store()
    action = args.sub_action
    if action == "list":
        subs = store.data.get("subscriptions", [])
        if not subs:
            print("（无订阅）")
        for s in subs:
            print(f"  {s['id']}  {s['name']}  节点{s['count']}  更新于 {s['updated'] or '从未'}\n      {s['url']}")
        return
    if action == "add":
        sub = store.add_subscription(args.name or "订阅", args.url)
        cnt, errs = manager.refresh_subscription(store, sub["id"])
        store.save()
        for e in errs[:3]:
            print("  " + e)
        print(f"已添加订阅 {sub['id']}（{cnt} 个节点）")
        if args.apply:
            print(manager.apply_config(store)[1])
        return
    if action == "update":
        target = args.id or "all"
        if target == "all":
            res = manager.refresh_all_subscriptions(store)
            print(f"已更新 {len(res)} 个订阅，共 {sum(res.values())} 个节点")
        else:
            cnt, errs = manager.refresh_subscription(store, target)
            for e in errs[:3]:
                print("  " + e)
            print(f"已更新 {cnt} 个节点")
        store.save()
        if args.apply:
            print(manager.apply_config(store)[1])
        return
    if action == "del":
        ok = store.delete_subscription(args.id, remove_nodes=not args.keep_nodes)
        store.save()
        print("已删除" if ok else "订阅不存在")
        if ok and args.apply:
            print(manager.apply_config(store)[1])


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

    sub.add_parser("config", help="打印将生成的配置").set_defaults(func=cmd_config)

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
