<?php
// forgot_password.php
global $pdo;
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/cookie_utils.php';

// Eğer kullanıcı zaten giriş yapmışsa dashboard'a yönlendir
$user_id = getSecureCookie('user_id');
if ($user_id) {
    header("Location: dashboard.php");
    exit;
}

$errors = [];
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    if (empty($email)) {
        $errors[] = "E-posta adresi gerekli";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Geçerli bir e-posta adresi giriniz";
    }

    if (empty($errors)) {
        // Kullanıcıyı e-posta ile kontrol et
        $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $token = generateResetToken();
            if (saveResetToken($pdo, $user['id'], $token)) {
                sendPasswordResetEmail($user['email'], $user['username'], $token, "http://{$_SERVER['HTTP_HOST']}/auth/reset_password.php?token=%s");
                $success = true;
            } else {
                $errors[] = "Sistem hatası oluştu. Lütfen daha sonra tekrar deneyin.";
            }
        } else {
            // Kullanıcı bulunamadı - güvenlik için başarılı mesajı göster
            $success = true;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Şifremi Unuttum</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="container">
    <h2>Şifremi Unuttum</h2>

    <?php if (!empty($errors)): ?>
        <div class="error-message">
            <?php foreach ($errors as $error): ?>
                <p><?php echo htmlspecialchars($error); ?></p>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if ($success): ?>
        <div class="success-message">
            <p>Şifre sıfırlama bağlantısı e-posta adresinize gönderildi. Lütfen e-postanızı kontrol edin.</p>
            <p><a href="/auth/login.php">Giriş sayfasına dön</a></p>
        </div>
    <?php else: ?>
        <form action="/auth/forgot_password.php" method="post">
            <div class="form-group">
                <label for="email">E-posta Adresiniz:</label>
                <input type="email" name="email" id="email" value="<?php echo htmlspecialchars($email ?? ''); ?>" required>
            </div>

            <div class="form-group">
                <button type="submit" class="btn">Şifre Sıfırlama Bağlantısı Gönder</button>
            </div>

            <p><a href="/auth/login.php">Giriş sayfasına dön</a></p>
        </form>
    <?php endif; ?>
</div>
</body>
</html>