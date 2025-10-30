import base64
import json

def decode_jwt_payload(payload_b64url: str):
    """
    一个专门用于解码 JWT Payload 的函数，能正确处理 Padding 和 UTF-8 编码。
    
    Args:
        payload_b64url: 从 JWT 中提取的、使用 Base64Url 编码的 Payload 字符串。
        
    Returns:
        一个格式化好的 JSON 字符串，如果解码失败则返回错误信息。
    """
    try:
        # 步骤 1: 补全缺失的 Padding ('=')
        # Base64 字符串的长度必须是 4 的倍数。
        # JWT 常常省略末尾的 '='，我们需要把它加回去。
        missing_padding = len(payload_b64url) % 4
        if missing_padding:
            payload_b64url += '=' * (4 - missing_padding)
        # 步骤 2: 使用 urlsafe_b64decode 解码成二进制 bytes
        # 注意要用 urlsafe 版本，因为它能处理 JWT 中的 '-' 和 '_' 字符。
        decoded_bytes = base64.urlsafe_b64decode(payload_b64url)
        
        # 步骤 3: 使用 UTF-8 将二进制 bytes 解码成文本字符串
        # 这是解决中文乱码最关键的一步。
        decoded_string = decoded_bytes.decode('utf-8')
        
        # 步骤 4: (可选，为了美观) 将 JSON 字符串解析并格式化输出
        # ensure_ascii=False 确保中文字符能直接显示，而不是显示成 \uXXXX 的形式。
        parsed_json = json.loads(decoded_string)
        pretty_json = json.dumps(parsed_json, indent=4, ensure_ascii=False)
        
        return pretty_json
        
    except Exception as e:
        return f"解码失败: {e}"
# --- 主程序 ---
# 您提供的 JWT Payload
jwt_payload = ""

# 调用函数并打印结果
decoded_result = decode_jwt_payload(jwt_payload)
print("--- JWT Payload 解码结果 ---")
print(decoded_result)
