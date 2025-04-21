<?php
global $pdo;
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/cookie_utils.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (empty($username)) {
        $errors[] = "Kullanıcı adı gerekli";
    }

    if (empty($email)) {
        $errors[] = "E-posta adresi gerekli";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Geçerli bir e-posta adresi girin";
    }

    if (empty($password)) {
        $errors[] = "Şifre gerekli";
    } elseif (strlen($password) < 6) {
        $errors[] = "Şifre en az 6 karakter olmalı";
    }

    if ($password !== $confirm_password) {
        $errors[] = "Şifreler eşleşmiyor";
    }

    if (empty($errors)) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetchColumn() > 0) {
            $errors[] = "Bu kullanıcı adı zaten kullanılıyor";
        }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetchColumn() > 0) {
            $errors[] = "Bu e-posta adresi zaten kullanılıyor";
        }
    }

    if (empty($errors)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $pdo->prepare("INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, NOW())");

        if ($stmt->execute([$username, $email, $hashed_password])) {
            setSecureCookie('success_message' , 'Kayıt başarılı! Şimdi giriş yapabilirsiniz' , time() + 300);
            header("Location: login.php");
            exit;
        } else {
            $errors[] = "Bir hata oluştu, lütfen tekrar deneyin.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kayıt Ol</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="container">
    <h2>Kayıt Ol</h2>

    <?php if (!empty($errors)): ?>
        <div class="error-message">
            <?php foreach ($errors as $error): ?>
                <p><?php echo $error; ?></p>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <form action="register.php" method="post">
        <div class="form-group">
            <label for="username">Kullanıcı Adı:</label>
            <input type="text" name="username" id="username" value="<?php echo htmlspecialchars($username ?? ''); ?>">
        </div>

        <div class="form-group">
            <label for="email">E-posta:</label>
            <input type="email" name="email" id="email" value="<?php echo htmlspecialchars($email ?? ''); ?>">
        </div>

        <div class="form-group">
            <label for="password">Şifre:</label>
            <input type="password" name="password" id="password">
        </div>

        <div class="form-group">
            <label for="confirm_password">Şifreyi Tekrarla:</label>
            <input type="password" name="confirm_password" id="confirm_password">
        </div>

        <div class="form-group">
            <button type="submit" class="btn">Kayıt Ol</button>
        </div>

        <p>Zaten hesabınız var mı? <a href="login.php">Giriş Yap</a></p>
    </form>
</div>
</body>
</html>