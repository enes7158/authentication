<?php
global $pdo;
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/cookie_utils.php';

$user_id = getSecureCookie('user_id');
if ($user_id) {
    header("Location: dashboard.php");
    exit;
}

$errors = [];
$success = false;
$token_valid = false;
$token = $_GET['token'] ?? '';

if (empty($token)) {
    header("Location: /auth/login.php");
    exit;
}

$tokenData = validateResetToken($pdo, $token);
if ($tokenData) {
    $token_valid = true;
    $userId = $tokenData['user_id'];
} else {
    $errors[] = "Geçersiz veya süresi dolmuş bir şifre sıfırlama bağlantısı kullanıyorsunuz.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $token_valid) {
    $password = $_POST['password'] ?? '';
    $password_confirm = $_POST['password_confirm'] ?? '';

    if (empty($password)) {
        $errors[] = "Yeni şifre gerekli";
    } elseif (strlen($password) < 8) {
        $errors[] = "Şifre en az 8 karakter uzunluğunda olmalıdır";
    }

    if ($password !== $password_confirm) {
        $errors[] = "Şifreler eşleşmiyor";
    }

    if (empty($errors)) {
        if (resetPasswordAndLogin($pdo, $userId, $password, 'user_id')) {
            $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                setSecureCookie('username', $user['username'], time() + 86400 * 30, '/');
                setSecureCookie('success_message', 'Şifreniz başarıyla güncellendi ve giriş yaptınız.', time() + 60, '/');
                header("Location: /auth/dashboard.php");
                exit;
            } else {
                setSecureCookie('success_message', 'Şifreniz başarıyla güncellendi.', time() + 60, '/');
                header("Location: /auth/login.php");
                exit;
            }
        } else {
            $errors[] = "Şifre güncellenirken bir hata oluştu. Lütfen daha sonra tekrar deneyin.";
        }
    }
}
?>

    <!DOCTYPE html>
    <html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Şifre Sıfırlama</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="container">
    <h2>Şifre Sıfırlama</h2>

    <?php if (!empty($errors)): ?>
        <div class="error-message">
            <?php foreach ($errors as $error): ?>
                <p><?php echo htmlspecialchars($error); ?></p>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if ($token_valid): ?>
        <form action="/auth/reset_password.php?token=<?php echo htmlspecialchars($token); ?>" method="post">
            <div class="form-group">
                <label for="password">Yeni Şifre:</label>
                <input type="password" name="password" id="password" required>
            </div>

            <div class="form-group">
                <label for="password_confirm">Şifre Tekrar:</label>
                <input type="password" name="password_confirm" id="password_confirm" required>
            </div>

            <div class="form-group">
                <button type="submit" class="btn">Şifremi Güncelle</button>
            </div>
        </form>
    <?php else: ?>
        <p>Şifre sıfırlama bağlantınız geçersiz veya süresi dolmuş.</p>
        <p><a href="/auth/forgot_password.php">Yeni bir şifre sıfırlama bağlantısı talep edin</a></p>
    <?php endif; ?>

    <p><a href="/auth/login.php">Giriş sayfasına dön</a></p>
</div>
</body>
    </html><?php
