<?php
session_start();
header('Content-Type: application/json');

// 配置：请修改这个密钥，且不要让任何人知道
$SECRET_KEY = "ZMX_GAME_SECURITY_SALT_2026"; 
$MAX_PPS = 150; // 每秒最高得分上限，超过则判定为挂机/瞬移
$DATA_FILE = 'rankings.json';

// --- 接口：获取游戏开始 Token ---
if (isset($_GET['action']) && $_GET['action'] === 'start') {
    $_SESSION['game_start_time'] = microtime(true);
    $_SESSION['game_token'] = bin2hex(random_bytes(16));
    echo json_encode(['status' => 'success', 'token' => $_SESSION['game_token']]);
    exit;
}

// --- 接口：提交分数 ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['user'] ?? 'anonymous';
    $score = intval($_POST['score'] ?? 0);
    $client_sign = $_POST['sign'] ?? '';
    $token = $_POST['token'] ?? '';

    // 1. 验证 Session 和 Token
    if (!isset($_SESSION['game_token']) || $token !== $_SESSION['game_token']) {
        die(json_encode(['status' => 'error', 'message' => 'Invalid Session']));
    }

    // 2. 验证时间开销（反瞬移）
    $duration = microtime(true) - $_SESSION['game_start_time'];
    if ($duration < 1.0 || ($score / $duration) > $MAX_PPS) {
        // 判定为异常，但返回 success 迷惑对方，实际不记录
        die(json_encode(['status' => 'success', 'debug' => 'Anomaly detected']));
    }

    // 3. 核心签名校验（HMAC-SHA256）
    // 算法：sha256(user + score + token + SECRET_KEY)
    $expected_sign = hash_hmac('sha256', $user . $score . $token, $SECRET_KEY);
    if ($client_sign !== $expected_sign) {
        die(json_encode(['status' => 'success', 'debug' => 'Signature mismatch']));
    }

    // 4. 写入排行榜
    $rankings = json_decode(file_get_contents($DATA_FILE), true) ?: [];
    $rankings[] = ['user' => htmlspecialchars($user), 'score' => $score, 'time' => time()];
    usort($rankings, fn($a, $b) => $b['score'] <=> $a['score']);
    file_put_contents($DATA_FILE, json_encode(array_slice($rankings, 0, 10)));

    // 5. 销毁 Token 防止重用
    unset($_SESSION['game_token']);
    echo json_encode(['status' => 'success', 'rankings' => array_slice($rankings, 0, 10)]);
    exit;
}