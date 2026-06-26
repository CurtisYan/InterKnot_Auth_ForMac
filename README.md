# InterKnot Auth for macOS

InterKnot Auth for macOS 是广东天翼校园网认证工具的 macOS 原生适配版，使用 SwiftUI 和系统原生组件重做界面与交互。

本项目功能参考并迁移自原项目：

- 原项目：[Yish1/InterKnot_Auth](https://github.com/Yish1/InterKnot_Auth)
- 协议/流程参考：[Pandaft/ESurfingPy-CLI](https://github.com/Pandaft/ESurfingPy-CLI)

## 功能

- 广东天翼校园网登录与下线
- 自动获取或手动解析认证参数
- 登录验证码弹窗输入
- 登录后访问目标检测与延迟显示
- 看门狗检测与自动重连
- 多拨配置
- EasyTier 隧道配置
- 全局可展开运行日志
- 配置自动保存，密码可保存到 macOS Keychain

## 认证流程

1. 填写账号、密码和认证参数。
2. 点击登录后获取认证页和验证码。
3. 输入验证码并提交登录请求。
4. 登录成功后保存网关返回的 `signature`。
5. 点击注销时使用当前 `signature` 请求 `/ajax/logout` 下线。

如果不是通过本应用登录，应用通常拿不到当前会话的 `signature`，因此无法代替网页或官方客户端下线。

## 认证参数

自动获取认证参数需要连接校园网络，并关闭代理。

如果自动获取失败，可以在浏览器访问 `2.2.2.2`，复制跳转后的完整地址，在应用的“认证参数”页点击“手动解析”后粘贴解析。

## 构建

```sh
swift build
make bundle
```

打包后的应用位于：

```text
InterKnotAuth.app
```

如果应用已经打开，重新打包后需要退出旧进程再重新打开，运行中的 App 不会自动替换成新版本。
