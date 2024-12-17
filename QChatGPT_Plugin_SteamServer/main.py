from pkg.plugin.context import register, handler, BasePlugin, APIHost, EventContext
from pkg.plugin.events import PersonNormalMessageReceived, GroupNormalMessageReceived
from pkg.command import entities
from pkg.command.operator import CommandOperator, operator_class
import json
import os
import re
import socket
import struct
import asyncio
import sys
from typing import Dict, List, Optional, AsyncGenerator

# Windows下asyncio的补丁
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

@operator_class(name="ping", help="获取帮助请输入：！ping help", privilege=1)
class SteamServerOperator(CommandOperator):
    def __init__(self, host: APIHost):
        super().__init__(host)
        self.config_path = os.path.join(os.path.dirname(__file__), "config.json")
        self.logger = host.logger
        self.load_config()
        self.timeout = 5.0  # 设置查询超时时间

    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.servers = config.get('servers', {})
            else:
                self.save_default_config()
        except Exception as e:
            self.logger.error(f"加载配置文件失败: {str(e)}")
            self.save_default_config()

    def save_default_config(self):
        """保存默认配置"""
        default_config = {
            'servers': {
                'example': {
                    'ip': '127.0.0.1',
                    'port': '27015',
                    'description': '示例服务器'
                }
            }
        }
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, ensure_ascii=False, indent=2)
            self.servers = default_config['servers']
        except Exception as e:
            self.logger.error(f"保存默认配置失败: {str(e)}")

    async def query_server(self, ip: str, port: int) -> Optional[Dict]:
        """查询CS2服务器信息"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Source2引擎的A2S_INFO查询包
            query = b"\xFF\xFF\xFF\xFFTSource Engine Query\0"
            
            self.logger.info(f"正在查询服务器: {ip}:{port}")
            
            # 记录发送时间
            start_time = asyncio.get_event_loop().time()
            sock.sendto(query, (ip, port))
            
            try:
                response = sock.recv(1400)
                # 计算延迟（毫秒）
                latency = int((asyncio.get_event_loop().time() - start_time) * 1000)
                
                if response:
                    try:
                        # 检查是否是挑战响应
                        if response[4] == 0x41:  # 'A'
                            # 获取挑战码
                            challenge = response[5:9]
                            # 发送带有挑战码的查询
                            query = b"\xFF\xFF\xFF\xFFTSource Engine Query\0" + challenge
                            sock.sendto(query, (ip, port))
                            response = sock.recv(1400)
                        
                        if not response or len(response) < 5:
                            return None
                            
                        # 检查响应类型
                        if response[4] != 0x49:  # 'I'
                            self.logger.error(f"无效的响应类型: {response[4]}")
                            return None
                            
                        # 跳过包头和响应类型
                        pos = 5
                        
                        # 读取协议版本
                        protocol = response[pos]
                        pos += 1
                        
                        # 读取服务器名称
                        name_end = response.find(b"\0", pos)
                        name = response[pos:name_end].decode("utf-8", errors="ignore")
                        pos = name_end + 1
                        
                        # 读取地图名称
                        map_end = response.find(b"\0", pos)
                        map_name = response[pos:map_end].decode("utf-8", errors="ignore")
                        pos = map_end + 1
                        
                        # 读取游戏目录
                        dir_end = response.find(b"\0", pos)
                        game_dir = response[pos:dir_end].decode("utf-8", errors="ignore")
                        pos = dir_end + 1
                        
                        # 读取游戏描述
                        desc_end = response.find(b"\0", pos)
                        game_desc = response[pos:desc_end].decode("utf-8", errors="ignore")
                        pos = desc_end + 1
                        
                        # 读取Steam AppID
                        appid = struct.unpack("<H", response[pos:pos+2])[0]
                        pos += 2
                        
                        # 读取玩家数量
                        players = response[pos]
                        pos += 1
                        
                        # 读取最玩家数
                        max_players = response[pos]
                        pos += 1
                        
                        # 读取机器人数量
                        bots = response[pos]
                        pos += 1
                        
                        # 读取服务器类型
                        server_type = chr(response[pos])
                        pos += 1
                        
                        # 读取服务器环境
                        environment = chr(response[pos])
                        pos += 1
                        
                        # 读取服务器可见性
                        visibility = response[pos]
                        pos += 1
                        
                        # 读取VAC状态
                        vac = response[pos]
                        pos += 1
                        
                        # 读取版本
                        version_end = response.find(b"\0", pos)
                        version = response[pos:version_end].decode("utf-8", errors="ignore") if version_end != -1 else "未知"
                        pos = version_end + 1 if version_end != -1 else pos
                        
                        # 读取额外数据（EDF）
                        if pos < len(response):
                            edf = response[pos]
                            pos += 1
                            
                            # 如果有标签数据
                            if edf & 0x01:
                                tags_end = response.find(b"\0", pos)
                                tags = response[pos:tags_end].decode("utf-8", errors="ignore") if tags_end != -1 else ""
                                pos = tags_end + 1 if tags_end != -1 else pos
                            else:
                                tags = ""
                        else:
                            tags = ""
                        
                        # 获取操作系统/平台信息
                        platform = "Windows" if environment == "w" else "Linux" if environment == "l" else "Mac" if environment == "m" else "未知"
                        
                        return {
                            "name": name,
                            "map": map_name,
                            "game": game_dir,
                            "description": game_desc,
                            "appid": appid,
                            "players": players,
                            "max_players": max_players,
                            "bots": bots,
                            "server_type": server_type,
                            "environment": environment,
                            "visibility": "Private" if visibility else "Public",
                            "vac": "Secured" if vac else "Unsecured",
                            "protocol": protocol,
                            "ip": ip,
                            "port": port,
                            "latency": latency,
                            "platform": platform,
                            "version": version,
                            "tags": tags
                        }
                        
                    except Exception as e:
                        self.logger.error(f"解析响应数据时出错: {str(e)}")
                        self.logger.error(f"原始响应: {response.hex()}")
                        return None
                        
            except socket.timeout:
                self.logger.error(f"查询超时: {ip}:{port}")
            except Exception as e:
                self.logger.error(f"接收数据时出错: {str(e)}")
            
            return None
            
        except Exception as e:
            self.logger.error(f"查询出错: {str(e)}")
            return None
        finally:
            sock.close()

    def format_server_info(self, server_info: Dict) -> str:
        """格式化服务器信息"""
        try:
            if not server_info:
                return "无法获取服务器信息"

            info = [
                f"服务器名称: {server_info['name']}",
                f"地图: {server_info['map']}",
                f"游戏: {server_info['game']}",
                f"描述: {server_info['description']}",
                f"标签: {server_info.get('tags', '无')}",
                f"玩家数: {server_info['players']}/{server_info['max_players']}",
                f"延迟: {server_info['latency']}ms",
                f"平台: {server_info['platform']}",
                f"版本: {server_info['version']}",
                f"VAC状态: {server_info['vac']}",
                f"可见性: {server_info['visibility']}",
                "\nConnect命令:",
                f"connect {server_info['ip']}:{server_info['port']}"
            ]
            
            return "\n".join(info)
        except Exception as e:
            self.logger.error(f"格式化服务器信息失败: {str(e)}")
            return "格式化服务器信息时出错"

    async def query_server_with_retry(self, ip: str, port: int, max_retries: int = 2) -> Optional[Dict]:
        """带重试的服务器查询"""
        for attempt in range(max_retries + 1):
            try:
                info = await self.query_server(ip, port)
                if info:
                    return info
                if attempt < max_retries:
                    self.logger.info(f"服务器 {ip}:{port} 查询失败，正在进行第 {attempt + 2} 次尝试")
                    await asyncio.sleep(1)  # 等待1秒后重试
            except Exception as e:
                self.logger.error(f"第 {attempt + 1} 次查询出错: {str(e)}")
                if attempt < max_retries:
                    await asyncio.sleep(1)
        
        return None

    async def format_exg_servers_info(self, server_num: str = None) -> str:
        """查询并格式化EXG服务器信息，可选择查询单个服务器"""
        results = []
        exg_servers = {k: v for k, v in self.servers.items() if k.startswith('exg')}
        
        # 如果指定了服务器编号，只查询该服务器
        if server_num:
            server_id = f"exg{server_num}"
            if server_id not in exg_servers:
                return f"未找到编号为 {server_num} 的EXG服务器"
            servers_to_query = {server_id: exg_servers[server_id]}
        else:
            servers_to_query = exg_servers
        
        # 查询服务器
        for server_id, server in servers_to_query.items():
            try:
                info = await self.query_server_with_retry(server['ip'], int(server['port']))
                if info:
                    results.append({
                        'id': server_id,
                        'name': info['name'],
                        'map': info['map'],
                        'players': info['players'],
                        'max_players': info['max_players'],
                        'latency': info['latency'],
                        'platform': info['platform'],
                        'version': info['version'],
                        'ip': info['ip'],
                        'port': info['port']
                    })
                else:
                    results.append({
                        'id': server_id,
                        'status': 'offline',
                        'description': server.get('description', ''),
                        'ip': server['ip'],
                        'port': server['port']
                    })
            except Exception as e:
                self.logger.error(f"查询服务器 {server_id} 时出错: {str(e)}")
                results.append({
                    'id': server_id,
                    'status': 'error',
                    'description': server.get('description', ''),
                    'ip': server['ip'],
                    'port': server['port']
                })
        
        # 按服务器ID排序
        results.sort(key=lambda x: int(x['id'][3:]))
        
        # 格式化输出
        if not results:
            return "当前没有可用的EXG服务器"
        
        output = ["EXG服务器状态:"] if not server_num else []
        for server in results:
            if server.get('status') == 'offline':
                output.append(
                    f"{server['id'].upper()}: {server['description']}\n"
                    f"IP: {server['ip']}:{server['port']}\n"
                    f"状态: 离线\n"
                )
            elif server.get('status') == 'error':
                output.append(
                    f"{server['id'].upper()}: {server['description']}\n"
                    f"IP: {server['ip']}:{server['port']}\n"
                    f"状态: 查询失败\n"
                )
            else:
                output.append(
                    f"{server['id'].upper()}: {server['name']}\n"
                    f"IP: {server['ip']}:{server['port']}\n"
                    f"地图: {server['map']}\n"
                    f"玩家: {server['players']}/{server['max_players']}\n"
                    f"延迟: {server['latency']}ms | 平台: {server['platform']} | 版本: {server['version']}\n"
                )
        
        return "\n".join(output)

    async def format_tsuuz_servers_info(self, server_num: str = None) -> str:
        """查询并格式化TSUUZ服务器信息，可选择查询单个服务器"""
        results = []
        tsuuz_servers = {k: v for k, v in self.servers.items() if k.startswith('tsuuz')}
        
        # 如果指定了服务器编号，只查询该服务器
        if server_num:
            server_id = f"tsuuz{server_num}"
            if server_id not in tsuuz_servers:
                return f"未找到编号为 {server_num} 的TSUUZ服务器"
            servers_to_query = {server_id: tsuuz_servers[server_id]}
        else:
            servers_to_query = tsuuz_servers
        
        # 查询服务器
        for server_id, server in servers_to_query.items():
            try:
                info = await self.query_server_with_retry(server['ip'], int(server['port']))
                if info:
                    results.append({
                        'id': server_id,
                        'name': info['name'],
                        'map': info['map'],
                        'players': info['players'],
                        'max_players': info['max_players'],
                        'latency': info['latency'],
                        'platform': info['platform'],
                        'version': info['version'],
                        'ip': info['ip'],
                        'port': info['port']
                    })
                else:
                    results.append({
                        'id': server_id,
                        'status': 'offline',
                        'description': server.get('description', ''),
                        'ip': server['ip'],
                        'port': server['port']
                    })
            except Exception as e:
                self.logger.error(f"查询服务器 {server_id} 时出错: {str(e)}")
                results.append({
                    'id': server_id,
                    'status': 'error',
                    'description': server.get('description', ''),
                    'ip': server['ip'],
                    'port': server['port']
                })
        
        # 按服务器ID排序
        results.sort(key=lambda x: int(x['id'][5:]))
        
        # 格式化输出
        if not results:
            return "当前没有可用的TSUUZ服务器"
        
        output = ["TSUUZ服务器状态:"] if not server_num else []
        for server in results:
            if server.get('status') == 'offline':
                output.append(
                    f"{server['id'].upper()}: {server['description']}\n"
                    f"IP: {server['ip']}:{server['port']}\n"
                    f"状态: 离线\n"
                )
            elif server.get('status') == 'error':
                output.append(
                    f"{server['id'].upper()}: {server['description']}\n"
                    f"IP: {server['ip']}:{server['port']}\n"
                    f"状态: 查询失败\n"
                )
            else:
                output.append(
                    f"{server['id'].upper()}: {server['name']}\n"
                    f"IP: {server['ip']}:{server['port']}\n"
                    f"地图: {server['map']}\n"
                    f"玩家: {server['players']}/{server['max_players']}\n"
                    f"延迟: {server['latency']}ms | 平台: {server['platform']} | 版本: {server['version']}\n"
                )
        
        return "\n".join(output)

    async def handle_query(self, msg: str) -> str:
        """处理查询命令"""
        try:
            # 直接查询IP:端口
            ip_port_match = re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)$', msg.strip())
            if ip_port_match:
                ip, port = ip_port_match.groups()
                port = int(port)
                self.logger.info(f"收到查询请求: {ip}:{port}")
                
                server_info = await self.query_server_with_retry(ip, port)
                if server_info:
                    response = self.format_server_info(server_info)
                    self.logger.info(f"查询成功: {response}")
                else:
                    response = (
                        f"无法获取服务器 {ip}:{port} 的信息\n"
                        "可能原因：\n"
                        "1. 服务器离线或未响应\n"
                        "2. 服务器不接受Source查询\n"
                        "3. IP或端口不正确\n"
                        "4. 服务器防火墙阻止查询"
                    )
                    self.logger.info("查询失败")
                
                return response
            
            # 查询已保存的服务器
            server_id = msg.strip()
            if not server_id:
                if not self.servers:
                    return "当前没有保存的服务器。\n使用方法:\n1. !ping add <IP:端口> <描述> - 添加服务器\n2. !ping query <IP:端口> - 直接查询服务器"
                
                server_list = "\n".join([
                    f"{id}: {info['description']} ({info['ip']}:{info['port']})"
                    for id, info in self.servers.items()
                ])
                return f"已保存的服务器列表:\n{server_list}\n\n使用方法:\n1. !ping query <服务器ID>\n2. !ping query <IP:端口>"
            
            if server_id in self.servers:
                server = self.servers[server_id]
                server_info = await self.query_server(server['ip'], int(server['port']))
                if server_info:
                    return self.format_server_info(server_info)
                else:
                    return f"无法获取服务器 {server_id} ({server['ip']}:{server['port']}) 的信息，服务器可能离线"
            else:
                return f"未找到服务器 {server_id}，请使用 '!ping query' 命令查看可用服务器列表"
                
        except Exception as e:
            self.logger.error(f"处理查询命令时发生错误: {str(e)}")
            return f"处理命令时发生错误: {str(e)}"

    async def handle_add_server(self, server_id: str, ip_port: str, description: str) -> str:
        """处理添加服务器命令"""
        try:
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)$', ip_port.strip())
            if not match:
                return "IP:端口格式错误。正确格式：IP:端口，例如：127.0.0.1:27015"
            
            ip, port = match.groups()
            self.servers[server_id] = {
                'ip': ip,
                'port': port,
                'description': description
            }
            
            # 保存配置
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({'servers': self.servers}, f, ensure_ascii=False, indent=2)
            
            self.load_config()  # 重新加载配置
            
            return f"已添加服务器 {server_id}"
                
        except Exception as e:
            self.logger.error(f"处理添加服务器命令时发生错误: {str(e)}")
            return "处理命令时发生错误"

    async def execute(self, context: entities.ExecuteContext) -> AsyncGenerator[entities.CommandReturn, None]:
        command = context.crt_params[0] if context.crt_params else "help"
        
        if command == "query":
            query = context.crt_params[1] if len(context.crt_params) > 1 else ""
            response = await self.handle_query(query)
        elif command == "add":
            if str(context.query.launcher_type).split('.')[-1].lower() != "person":
                response = "只能在私聊中添加服务器"
            elif len(context.crt_params) < 3:
                response = "格式错误。正确格式：！ping add <IP:端口> <描述>"
            else:
                ip_port = context.crt_params[1]
                description = " ".join(context.crt_params[2:])
                server_id = ip_port.replace(":", "_")
                response = await self.handle_add_server(server_id, ip_port, description)
        elif command == "exg":
            server_num = context.crt_params[1] if len(context.crt_params) > 1 else None
            response = await self.format_exg_servers_info(server_num)
        elif command == "tsuuz":
            server_num = context.crt_params[1] if len(context.crt_params) > 1 else None
            response = await self.format_tsuuz_servers_info(server_num)
        elif command == "help":
            response = (
                "CS2服务器查询插件\n"
                "命令列表:\n"
                "1. ！ping query [服务器ID/IP:端口] - 查询服务器信息\n"
                "2. ！ping add <IP:端口> <描述> - 添加服务器(仅私聊)\n"
                "3. ！ping exg [编号或不加编号] - 查询EXG服务器状态\n"
                "4. ！ping tsuuz [编号或不加编号] - 查询TSUUZ服务器状态\n"
                "5. ！ping help - 显示帮助信息\n\n"
                "快速查询命令:\n"
                "查服:<服务器ID/IP:端口>\n"
                "！exg [编号] - 查询EXG服务器\n"
                "！tsuuz [编号] - 查询TSUUZ服务器"
            )
        else:
            response = "未知命令。使用 ！ping help 查看帮助"
            
        yield entities.CommandReturn(text=response)

@register(name="SteamServer", description="Steam服务器查询插件", version="0.1", author="assistant")
class SteamServer(BasePlugin):
    def __init__(self, host: APIHost):
        super().__init__(host)
        self.operator = SteamServerOperator(host)

    @handler(PersonNormalMessageReceived)
    async def on_person_message(self, ctx: EventContext):
        text = ctx.event.text_message.strip()
        if text.startswith(("查服:", "查服：")):
            query = text[3:].strip()
            response = await self.operator.handle_query(query)
            ctx.add_return("reply", [response])
            ctx.prevent_default()
        elif text.startswith(("!", "！")):
            # 处理EXG命令
            if text.lower().startswith(("!exg", "！exg")):
                parts = text.split()
                server_num = parts[1] if len(parts) > 1 else None
                response = await self.operator.format_exg_servers_info(server_num)
                ctx.add_return("reply", [response])
                ctx.prevent_default()
            # 处理TSUUZ命令
            elif text.lower().startswith(("!tsuuz", "！tsuuz")):
                parts = text.split()
                server_num = parts[1] if len(parts) > 1 else None
                response = await self.operator.format_tsuuz_servers_info(server_num)
                ctx.add_return("reply", [response])
                ctx.prevent_default()

    @handler(GroupNormalMessageReceived)
    async def on_group_message(self, ctx: EventContext):
        text = ctx.event.text_message.strip()
        
        # 处理带感叹号的命令（不需要@）
        if text.startswith(("!", "！")):
            # 处理EXG命令
            if text.lower().startswith(("!exg", "！exg")):
                parts = text.split()
                server_num = parts[1] if len(parts) > 1 else None
                response = await self.operator.format_exg_servers_info(server_num)
                ctx.add_return("reply", [response])
                ctx.prevent_default()
                return
            
            # 处理TSUUZ命令
            if text.lower().startswith(("!tsuuz", "！tsuuz")):
                parts = text.split()
                server_num = parts[1] if len(parts) > 1 else None
                response = await self.operator.format_tsuuz_servers_info(server_num)
                ctx.add_return("reply", [response])
                ctx.prevent_default()
                return
            
            # 处理ping命令
            if text.lower().startswith(("!ping", "！ping")):
                # 移除命令前缀并分割参数
                parts = text[len("!ping"):].strip().split()
                # 创建执行上下文
                exec_context = entities.ExecuteContext(
                    query=ctx.event,
                    crt_params=parts
                )
                # 执行命令
                async for result in self.operator.execute(exec_context):
                    ctx.add_return("reply", [result.text])
                ctx.prevent_default()
                return
        
        # 处理需要@的命令
        if ctx.event.is_at:
            # 处理查服命令
            if text.startswith(("查服:", "查服：")):
                query = text[3:].strip()
                response = await self.operator.handle_query(query)
                ctx.add_return("reply", [response])
                ctx.prevent_default()

    def __del__(self):
        pass
