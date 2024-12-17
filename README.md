# QChatGPT Steam服务器查询插件

这是一个用于查询CS2/Steam服务器信息的QChatGPT插件。

## 功能

- 直接查询CS2/Steam服务器信息
- 保存常用服务器列表
- 显示服务器详细信息（名称、地图、玩家数等）
- 生成服务器连接命令

## 使用方法

### 基本命令

1. 直接查询服务器：
   ```
   !steamserver query IP:端口
   ```
   例如：`!steamserver query 202.189.10.36:27001`

2. 查看已保存的服务器列表：
   ```
   !steamserver query
   ```

3. 添加服务器到列表：
   ```
   !steamserver add 服务器ID IP:端口 描述
   ```
   例如：`!steamserver add my_server 202.189.10.36:27001 我的服务器`

### 查询结果包含

- 服务器名称
- 当前地图
- 游戏类型
- 玩家数量（包括机器人）
- VAC状态
- 服务器可见性
- 连接命令

## 配置文件

配置文件 `config.json` 用于保存服务器列表：

```json
{
    "servers": {
        "server_id": {
            "ip": "服务器IP",
            "port": "服务器端口",
            "description": "服务器描述"
        }
    }
}
```
