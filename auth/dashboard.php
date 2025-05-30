<?php
global $pdo;
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/cookie_utils.php';

$user_id = getSecureCookie('user_id');
if (!$user_id) {
    header("Location: login.php");
    exit;
}

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    deleteSecureCookie('user_id');
    deleteSecureCookie('username');
    header("Location: login.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kontrol Paneli</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="container">
    <header class="dashboard-header">
        <h2>Hoş Geldiniz, <?php echo htmlspecialchars($user['username']); ?>!</h2>
        <a href="logout.php" class="btn btn-logout">Çıkış Yap</a>
    </header>

    <div class="dashboard-content">
        <div class="user-info">
            <h3>Hesap Bilgileriniz</h3>
            <p><strong>Kullanıcı Adı:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
            <p><strong>E-posta:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
        </div>
    </div>
</div>
</body>
</html>