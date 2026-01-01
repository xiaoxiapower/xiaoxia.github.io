<?php
// 定义存储聊天数据的JSON文件路径
$chatFile = 'chat_data.json';
$usersFile = 'active_users.json';

// 确保文件存在并具有正确的初始结构
if (!file_exists($chatFile)) {
    file_put_contents($chatFile, json_encode([]));
}

if (!file_exists($usersFile)) {
    file_put_contents($usersFile, json_encode(['active' => []]));
}

// 获取用户真实IP地址的函数
function getUserIP() {
    $ip = '';
    
    // 检查是否有代理
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    
    // 如果是多个IP（通过代理），取第一个
    if (strpos($ip, ',') !== false) {
        $ipArray = explode(',', $ip);
        $ip = trim($ipArray[0]);
    }
    
    // 验证IP地址格式
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    } else {
        return '未知IP';
    }
}

// 处理用户登录/设置用户名
$currentUser = '';
$loginError = '';
$currentIP = getUserIP(); // 获取当前用户IP

// 处理用户登录表单提交
if (isset($_POST['action']) && $_POST['action'] === 'login' && !empty(trim($_POST['username']))) {
    $username = trim($_POST['username']);
    
    // 简单的用户名验证
    if (strlen($username) < 2) {
        $loginError = '用户名至少需要2个字符';
    } elseif (strlen($username) > 20) {
        $loginError = '用户名不能超过20个字符';
    } else {
        // 只保留字母、数字、下划线和中文
        if (!preg_match('/^[\w\x{4e00}-\x{9fa5}]+$/u', $username)) {
            $loginError = '用户名只能包含字母、数字、下划线和中文';
        } else {
            $currentUser = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
            
            // 将用户添加到活跃用户列表
            $users = json_decode(file_get_contents($usersFile), true);
            // 确保active键存在
            if (!isset($users['active'])) {
                $users['active'] = [];
            }
            $users['active'][$currentUser] = [
                'last_active' => time(),
                'ip' => $currentIP
            ];
            file_put_contents($usersFile, json_encode($users));
            
            // 设置session和cookie保存用户名
            session_start();
            $_SESSION['chat_username'] = $currentUser;
            setcookie('chat_username', $currentUser, time() + (86400 * 7), "/");
            
            // 重定向到聊天页面
            header("Location: " . $_SERVER['PHP_SELF']);
            exit();
        }
    }
}

// 检查用户是否已经登录
session_start();
if (isset($_SESSION['chat_username'])) {
    $currentUser = $_SESSION['chat_username'];
    
    // 更新用户活动时间和IP
    $users = json_decode(file_get_contents($usersFile), true);
    // 确保active键存在
    if (!isset($users['active'])) {
        $users['active'] = [];
    }
    
    $users['active'][$currentUser] = [
        'last_active' => time(),
        'ip' => $currentIP
    ];
    file_put_contents($usersFile, json_encode($users));
} elseif (isset($_COOKIE['chat_username'])) {
    $currentUser = $_COOKIE['chat_username'];
    $_SESSION['chat_username'] = $currentUser;
    
    // 更新用户活动时间和IP
    $users = json_decode(file_get_contents($usersFile), true);
    // 确保active键存在
    if (!isset($users['active'])) {
        $users['active'] = [];
    }
    
    $users['active'][$currentUser] = [
        'last_active' => time(),
        'ip' => $currentIP
    ];
    file_put_contents($usersFile, json_encode($users));
}

// 处理退出登录
if (isset($_POST['action']) && $_POST['action'] === 'logout') {
    // 从活跃用户中移除
    if ($currentUser) {
        $users = json_decode(file_get_contents($usersFile), true);
        if (isset($users['active'][$currentUser])) {
            unset($users['active'][$currentUser]);
            file_put_contents($usersFile, json_encode($users));
        }
    }
    
    // 清除session和cookie
    session_destroy();
    setcookie('chat_username', '', time() - 3600, "/");
    
    // 重定向到登录页面
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// 处理发送消息
if (isset($_POST['action']) && $_POST['action'] === 'send_message' && !empty(trim($_POST['message'])) && $currentUser) {
    $message = htmlspecialchars(trim($_POST['message']), ENT_QUOTES, 'UTF-8');
    $timestamp = time();
    
    // 限制消息长度
    if (strlen($message) > 500) {
        $message = substr($message, 0, 500) . '...';
    }
    
    // 读取现有聊天记录
    $chatData = json_decode(file_get_contents($chatFile), true);
    if (!$chatData) {
        $chatData = [];
    }
    
    // 添加新消息（包含IP地址）
    $chatData[] = [
        'username' => $currentUser,
        'message' => $message,
        'timestamp' => $timestamp,
        'time' => date('Y-m-d H:i:s', $timestamp),
        'ip' => $currentIP
    ];
    
    // 保存聊天记录（限制最多200条消息）
    if (count($chatData) > 200) {
        $chatData = array_slice($chatData, -200);
    }
    
    file_put_contents($chatFile, json_encode($chatData));
    
    // 重定向以避免重复提交
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// 处理清除聊天记录
if (isset($_POST['action']) && $_POST['action'] === 'clear_chat' && $currentUser) {
    file_put_contents($chatFile, json_encode([]));
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// 读取聊天记录
$chatData = json_decode(file_get_contents($chatFile), true);
if (!$chatData) {
    $chatData = [];
}

// 读取活跃用户（过去10分钟内有活动的用户视为在线）
$users = json_decode(file_get_contents($usersFile), true);
$onlineUsers = [];
$onlineUsersWithIP = [];

// 检查用户数据是否有效
if ($users && isset($users['active']) && is_array($users['active'])) {
    $tenMinutesAgo = time() - 600;
    foreach ($users['active'] as $username => $userData) {
        // 确保userData是数组并且包含last_active键
        if (is_array($userData) && isset($userData['last_active'])) {
            $lastActive = $userData['last_active'];
            $ip = isset($userData['ip']) ? $userData['ip'] : '未知IP';
        } elseif (is_numeric($userData)) {
            // 兼容旧格式：如果userData是数字（时间戳）
            $lastActive = $userData;
            $ip = '未知IP';
        } else {
            // 无效数据，跳过
            continue;
        }
        
        if ($lastActive > $tenMinutesAgo) {
            $onlineUsers[] = $username;
            $onlineUsersWithIP[$username] = $ip;
        }
    }
}

// 获取IP地址的简短版本（可选，用于显示）
function getShortIP($ip) {
    if ($ip === '未知IP' || $ip === '' || $ip === null) {
        return '未知IP';
    }
    
    // 选项3：显示前三段，最后一段用*隐藏
    $ipParts = explode('.', $ip);
    if (count($ipParts) === 4) {
        return $ipParts[0] . '.' . $ipParts[1] . '.' . $ipParts[2] . '.*';
    }
    
    // 如果是IPv6地址，进行类似处理
    if (strpos($ip, ':') !== false) {
        $ipParts = explode(':', $ip);
        if (count($ipParts) > 2) {
            return $ipParts[0] . ':' . $ipParts[1] . ':***';
        }
    }
    
    return $ip;
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>神秘的聊天室</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #4a6fa5;
            --secondary-color: #166088;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
            --success-color: #28a745;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #17a2b8;
            --border-radius: 8px;
            --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }

        [data-theme="dark"] {
            --primary-color: #5a86c2;
            --secondary-color: #2d7bb6;
            --light-color: #2d3748;
            --dark-color: #f8f9fa;
            --bg-color: #1a202c;
            --text-color: #e2e8f0;
            --card-bg: #2d3748;
            --border-color: #4a5568;
        }

        [data-theme="light"] {
            --bg-color: #f5f7fa;
            --text-color: #333;
            --card-bg: #ffffff;
            --border-color: #ddd;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            transition: var(--transition);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 15px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding: 20px;
            background-color: var(--card-bg);
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            flex-wrap: wrap;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .logo i {
            font-size: 2rem;
            color: var(--primary-color);
        }

        .logo h1 {
            font-size: 1.8rem;
        }

        .theme-toggle {
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: var(--border-radius);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: var(--transition);
        }

        .theme-toggle:hover {
            background: var(--secondary-color);
        }

        .main-content {
            display: grid;
            grid-template-columns: 1fr;
            gap: 25px;
        }

        @media (min-width: 992px) {
            .main-content {
                grid-template-columns: 1fr 1fr;
            }
        }

        .card {
            background-color: var(--card-bg);
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            padding: 25px;
            height: fit-content;
        }

        .card h2 {
            margin-bottom: 20px;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .card h2 i {
            font-size: 1.5rem;
        }

        .login-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .form-group label {
            font-weight: 600;
        }

        .form-control {
            padding: 12px 15px;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            background-color: var(--card-bg);
            color: var(--text-color);
            font-size: 1rem;
            transition: var(--transition);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(74, 111, 165, 0.2);
        }

        .btn {
            padding: 12px 20px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: var(--border-radius);
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .btn:hover {
            background-color: var(--secondary-color);
        }

        .btn-success {
            background-color: var(--success-color);
        }

        .btn-success:hover {
            background-color: #218838;
        }

        .btn-warning {
            background-color: var(--warning-color);
            color: #212529;
        }

        .btn-warning:hover {
            background-color: #e0a800;
        }

        .btn-info {
            background-color: var(--info-color);
            color: white;
        }

        .btn-info:hover {
            background-color: #138496;
        }

        .chat-container {
            display: flex;
            flex-direction: column;
            height: 500px;
        }

        .chat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }

        .online-count {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 600;
            color: var(--success-color);
        }

        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            background-color: var(--bg-color);
        }

        .message {
            padding: 12px 15px;
            margin-bottom: 15px;
            border-radius: var(--border-radius);
            background-color: var(--card-bg);
            border-left: 4px solid var(--primary-color);
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .message-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.9rem;
            flex-wrap: wrap;
        }

        .message-user-info {
            display: flex;
            flex-direction: column;
            gap: 3px;
        }

        .username {
            font-weight: 700;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .ip-address {
            font-size: 0.8rem;
            color: var(--info-color);
            background-color: rgba(23, 162, 184, 0.1);
            padding: 2px 8px;
            border-radius: 10px;
            display: inline-block;
        }

        .timestamp {
            color: #888;
            font-size: 0.85rem;
            align-self: flex-end;
        }

        .message-content {
            word-wrap: break-word;
            margin-top: 8px;
        }

        .chat-form {
            display: flex;
            gap: 10px;
        }

        .chat-input {
            flex: 1;
            padding: 12px 15px;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            background-color: var(--card-bg);
            color: var(--text-color);
            font-size: 1rem;
        }

        .chat-input:focus {
            outline: none;
            border-color: var(--primary-color);
        }

        .info-box {
            background-color: rgba(74, 111, 165, 0.1);
            border-left: 4px solid var(--primary-color);
            padding: 15px;
            border-radius: var(--border-radius);
            margin-top: 20px;
        }

        .info-box h3 {
            margin-bottom: 10px;
            color: var(--primary-color);
        }

        .info-list {
            padding-left: 20px;
        }

        .info-list li {
            margin-bottom: 8px;
        }

        footer {
            margin-top: 40px;
            text-align: center;
            padding: 20px;
            color: #888;
            font-size: 0.9rem;
            border-top: 1px solid var(--border-color);
        }

        .notification {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 15px 25px;
            background-color: var(--success-color);
            color: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            z-index: 1000;
            display: none;
            align-items: center;
            gap: 10px;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .error-message {
            background-color: var(--danger-color);
            color: white;
            padding: 12px 15px;
            border-radius: var(--border-radius);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .error-message i {
            font-size: 1.2rem;
        }

        .welcome-message {
            background-color: rgba(40, 167, 69, 0.1);
            padding: 20px;
            border-radius: var(--border-radius);
            margin-bottom: 20px;
        }

        .welcome-message p {
            margin-bottom: 10px;
        }

        .user-status {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
        }

        .user-status i {
            color: var(--success-color);
            font-size: 1.2rem;
        }

        .online-users {
            margin-top: 20px;
        }

        .online-users h4 {
            margin-bottom: 10px;
            color: var(--primary-color);
        }

        .user-tag {
            display: inline-block;
            background-color: rgba(74, 111, 165, 0.2);
            color: var(--primary-color);
            padding: 5px 10px;
            border-radius: 15px;
            margin: 0 5px 8px 0;
            font-size: 0.9rem;
        }

        .user-tag.self {
            background-color: rgba(40, 167, 69, 0.3);
            color: var(--success-color);
            font-weight: bold;
        }

        .ip-tag {
            font-size: 0.7rem;
            color: var(--info-color);
            margin-left: 5px;
        }

        .ip-display {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 10px;
            padding: 8px 12px;
            background-color: rgba(23, 162, 184, 0.1);
            border-radius: var(--border-radius);
            font-size: 0.9rem;
        }

        .ip-display i {
            color: var(--info-color);
        }

        .controls {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        @media (max-width: 768px) {
            header {
                flex-direction: column;
                gap: 15px;
                align-items: flex-start;
            }
            
            .chat-form {
                flex-direction: column;
            }
            
            .chat-container {
                height: 400px;
            }
            
            .message-header {
                flex-direction: column;
                gap: 5px;
            }
            
            .timestamp {
                align-self: flex-start;
            }
            
            .controls {
                flex-direction: column;
            }
        }
    </style>
</head>
<body data-theme="light">
    <div class="container">
        <header>
            <div class="logo">
                <i class="fas fa-comments"></i>
                <h1>神秘的聊天室</h1>
            </div>
            <button class="theme-toggle" id="themeToggle">
                <i class="fas fa-moon"></i>
                <span>深色主题</span>
            </button>
        </header>
        
        <div class="main-content">
            <!-- 用户登录/设置区域 -->
            <div class="card">
                <h2><i class="fas fa-user"></i> 用户设置</h2>
                
                <?php if (!$currentUser): ?>
                <form method="POST" class="login-form">
                    <input type="hidden" name="action" value="login">
                    
                    <?php if ($loginError): ?>
                    <div class="error-message">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?php echo $loginError; ?></span>
                    </div>
                    <?php endif; ?>
                    
                    <div class="form-group">
                        <label for="username">请输入用户名加入聊天室</label>
                        <input type="text" id="username" name="username" class="form-control" 
                               placeholder="输入您的用户名（2-20个字符）..." 
                               value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                               required>
                        <small style="color: #888; margin-top: 5px;">支持中文、字母、数字和下划线</small>
                    </div>
                    
                    <div class="ip-display">
                        <i class="fas fa-network-wired"></i>
                        <span>您的IP地址: <strong><?php echo $currentIP; ?></strong></span>
                    </div>
                    
                    <button type="submit" class="btn">
                        <i class="fas fa-sign-in-alt"></i> 加入聊天室
                    </button>
                </form>
                <?php else: ?>
                <div class="user-status">
                    <i class="fas fa-check-circle"></i>
                    <div>
                        <p>欢迎回来, <strong><?php echo $currentUser; ?></strong>!</p>
                        <p>您已登录聊天室，可以开始聊天了。</p>
                    </div>
                </div>
                
                <div class="ip-display">
                    <i class="fas fa-network-wired"></i>
                    <span>您的IP地址: <strong><?php echo $currentIP; ?></strong></span>
                </div>
                
                <div class="controls">
                    <form method="POST">
                        <input type="hidden" name="action" value="logout">
                        <button type="submit" class="btn btn-warning">
                            <i class="fas fa-sign-out-alt"></i> 退出登录
                        </button>
                    </form>
                    
                    <button class="btn btn-info" onclick="toggleIPVisibility()">
                        <i class="fas fa-eye"></i> <span id="ipToggleText">隐藏IP</span>
                    </button>
                </div>
                
                <div class="online-users">
                    <h4><i class="fas fa-users"></i> 当前在线用户 (<?php echo count($onlineUsers); ?>)</h4>
                    <div>
                        <?php foreach ($onlineUsersWithIP as $username => $ip): ?>
                            <span class="user-tag <?php echo ($username === $currentUser) ? 'self' : ''; ?>">
                                <?php echo $username; ?>
                                <span class="ip-tag ip-hidden"><?php echo getShortIP($ip); ?></span>
                            </span>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
                
                <div class="info-box">
                    <h3><i class="fas fa-info-circle"></i> 聊天室说明</h3>
                    <ul class="info-list">
                        <li>聊天数据存储在本地JSON文件中</li>
                        <li>在线用户检测时间：10分钟</li>
                    </ul>
                </div>
            </div>
            
            <!-- 聊天区域 -->
            <div class="card">
                <div class="chat-header">
                    <h2><i class="fas fa-comments"></i> 公共聊天室</h2>
                    <div class="online-count">
                        <i class="fas fa-user-friends"></i>
                        <span>在线用户: <?php echo count($onlineUsers); ?></span>
                    </div>
                </div>
                
                <?php if ($currentUser): ?>
                <div class="chat-container">
                    <div class="chat-messages" id="chatMessages">
                        <?php if (empty($chatData)): ?>
                            <div class="message">
                                <div class="message-header">
                                    <div class="message-user-info">
                                        <span class="username">系统消息</span>
                                    </div>
                                    <span class="timestamp"><?php echo date('Y-m-d H:i:s'); ?></span>
                                </div>
                                <div class="message-content">
                                    欢迎来到聊天室！你是第一个发言的人，快向大家问好吧！
                                </div>
                            </div>
                        <?php else: ?>
                            <?php foreach (array_reverse($chatData) as $msg): ?>
                            <div class="message">
                                <div class="message-header">
                                    <div class="message-user-info">
                                        <div class="username">
                                            <?php echo $msg['username']; ?>
                                            <?php if ($msg['username'] === $currentUser): ?>
                                            <i class="fas fa-user" style="font-size: 0.8rem;"></i>
                                            <?php endif; ?>
                                        </div>
                                        <span class="ip-address ip-hidden">
                                            <i class="fas fa-network-wired"></i> 
                                            IP: <?php echo isset($msg['ip']) ? getShortIP($msg['ip']) : '未知IP'; ?>
                                        </span>
                                    </div>
                                    <span class="timestamp"><?php echo $msg['time']; ?></span>
                                </div>
                                <div class="message-content">
                                    <?php echo $msg['message']; ?>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <form method="POST" class="chat-form">
                        <input type="hidden" name="action" value="send_message">
                        <input type="text" name="message" class="chat-input" placeholder="输入消息..." required maxlength="500">
                        <button type="submit" class="btn btn-success">
                            <i class="fas fa-paper-plane"></i> 发送
                        </button>
                    </form>
                    
                    <div class="controls">
                        <form method="POST">
                            <input type="hidden" name="action" value="clear_chat">
                            <button type="submit" class="btn" onclick="return confirm('确定要清除所有聊天记录吗？');">
                                <i class="fas fa-trash-alt"></i> 清除聊天记录
                            </button>
                        </form>
                        
                        <button class="btn btn-info" onclick="toggleMessageIPs()">
                            <i class="fas fa-eye"></i> <span id="messageIPToggleText">隐藏消息IP</span>
                        </button>
                    </div>
                </div>
                <?php else: ?>
                <div style="text-align: center; padding: 40px 20px;">
                    <i class="fas fa-comment-slash" style="font-size: 3rem; color: #ccc; margin-bottom: 20px;"></i>
                    <h3>请先登录加入聊天室</h3>
                    <p>在左侧表格中输入用户名后即可开始聊天</p>
                </div>
                <?php endif; ?>
            </div>
        </div>
        
        <footer>
            <p>一个神秘的网页聊天室 &copy; <?php echo date('Y'); ?> - 基于PHP和JSON文件存储</p>
            <p>消息总数: <?php echo count($chatData); ?> | 当前在线: <?php echo count($onlineUsers); ?> 人 | 您的IP: <?php echo $currentIP; ?></p>
        </footer>
    </div>
    
    <div class="notification" id="notification">
        <i class="fas fa-check-circle"></i>
        <span>消息发送成功！</span>
    </div>

    <script>
        // 主题切换功能
        const themeToggle = document.getElementById('themeToggle');
        const body = document.body;
        const themeIcon = themeToggle.querySelector('i');
        const themeText = themeToggle.querySelector('span');
        
        // 检查本地存储的主题偏好
        const savedTheme = localStorage.getItem('chatTheme') || 'light';
        body.setAttribute('data-theme', savedTheme);
        updateThemeButton(savedTheme);
        
        themeToggle.addEventListener('click', () => {
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('chatTheme', newTheme);
            updateThemeButton(newTheme);
        });
        
        function updateThemeButton(theme) {
            if (theme === 'dark') {
                themeIcon.className = 'fas fa-sun';
                themeText.textContent = '浅色主题';
            } else {
                themeIcon.className = 'fas fa-moon';
                themeText.textContent = '深色主题';
            }
        }
        
        // IP地址显示/隐藏功能
        let ipVisible = true;
        let messageIPVisible = true;
        
        function toggleIPVisibility() {
            const ipTags = document.querySelectorAll('.ip-tag');
            const toggleBtn = document.querySelector('#ipToggleText');
            
            ipVisible = !ipVisible;
            
            ipTags.forEach(tag => {
                if (ipVisible) {
                    tag.style.display = 'inline';
                } else {
                    tag.style.display = 'none';
                }
            });
            
            toggleBtn.textContent = ipVisible ? '隐藏IP' : '显示IP';
            localStorage.setItem('ipVisible', ipVisible);
        }
        
        function toggleMessageIPs() {
            const messageIPs = document.querySelectorAll('.ip-address');
            const toggleBtn = document.querySelector('#messageIPToggleText');
            
            messageIPVisible = !messageIPVisible;
            
            messageIPs.forEach(ip => {
                if (messageIPVisible) {
                    ip.style.display = 'inline-block';
                } else {
                    ip.style.display = 'none';
                }
            });
            
            toggleBtn.textContent = messageIPVisible ? '隐藏消息IP' : '显示消息IP';
            localStorage.setItem('messageIPVisible', messageIPVisible);
        }
        
        // 自动滚动到聊天区域底部
        const chatMessages = document.getElementById('chatMessages');
        if (chatMessages) {
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        // 消息发送后显示通知
        <?php if (isset($_POST['action']) && $_POST['action'] === 'send_message' && $currentUser): ?>
        document.addEventListener('DOMContentLoaded', function() {
            const notification = document.getElementById('notification');
            notification.style.display = 'flex';
            
            setTimeout(() => {
                notification.style.display = 'none';
            }, 3000);
        });
        <?php endif; ?>
        
        // 自动刷新聊天内容（每20秒）
        setInterval(() => {
            // 只有当用户已登录且聊天窗口可见时才刷新
            if (<?php echo $currentUser ? 'true' : 'false'; ?>) {
                location.reload();
            }
        }, 20000);
        
        // 防止表单重复提交
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function() {
                const submitBtn = this.querySelector('button[type="submit"]');
                if (submitBtn && !submitBtn.disabled) {
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 处理中...';
                }
            });
        });
        
        // 回车键发送消息
        document.addEventListener('DOMContentLoaded', function() {
            const messageInput = document.querySelector('input[name="message"]');
            if (messageInput) {
                messageInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        const sendButton = document.querySelector('button[type="submit"]');
                        if (sendButton && !sendButton.disabled) {
                            sendButton.click();
                        }
                    }
                });
            }
        });
        
        // 自动聚焦到用户名输入框
        document.addEventListener('DOMContentLoaded', function() {
            const usernameInput = document.getElementById('username');
            if (usernameInput && !<?php echo $currentUser ? 'true' : 'false'; ?>) {
                usernameInput.focus();
            }
            
            // 恢复IP显示设置
            const savedIPVisible = localStorage.getItem('ipVisible');
            const savedMessageIPVisible = localStorage.getItem('messageIPVisible');
            
            if (savedIPVisible === 'false') {
                toggleIPVisibility();
            }
            
            if (savedMessageIPVisible === 'false') {
                toggleMessageIPs();
            }
        });
        
        // 复制IP地址到剪贴板的功能
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                const notification = document.getElementById('notification');
                notification.querySelector('span').textContent = 'IP地址已复制到剪贴板';
                notification.style.display = 'flex';
                notification.style.backgroundColor = 'var(--info-color)';
                
                setTimeout(() => {
                    notification.style.display = 'none';
                }, 2000);
            });
        }
        
        // 为IP地址添加点击复制功能
        document.addEventListener('DOMContentLoaded', function() {
            const ipDisplays = document.querySelectorAll('.ip-address, .ip-display strong');
            ipDisplays.forEach(ipDisplay => {
                ipDisplay.style.cursor = 'pointer';
                ipDisplay.title = '点击复制IP地址';
                ipDisplay.addEventListener('click', function() {
                    const ipText = this.textContent.replace('IP:', '').trim();
                    copyToClipboard(ipText);
                });
            });
        });
    </script>
</body>
</html>