<?php
global $pdo;
require_once __DIR__ . '/../config.php';

if (isset($_COOKIE['user_id'])) {
    header("Location: dashboard.php");
    exit;
}

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($username)) {
        $errors[] = "Kullanıcı adı gerekli";
    }

    if (empty($password)) {
        $errors[] = "Şifre gerekli";
    }

    if (empty($errors)) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            setcookie('user_id', $user['id'], 0 ,"/");
            setcookie('username', $user['username'], 0 ,"/");

            header("Location: dashboard.php");
            exit;
        } else {
            $errors[] = "Geçersiz kullanıcı adı veya şifre";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Giriş Yap</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="container">
    <h2>Giriş Yap</h2>

    <?php if (!empty($errors)): ?>
        <div class="error-message">
            <?php foreach ($errors as $error): ?>
                <p><?php echo $error; ?></p>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if (isset($_SESSION['success_message'])): ?>
        <div class="success-message">
            <p><?php echo $_SESSION['success_message']; ?></p>
        </div>
        <?php unset($_SESSION['success_message']); ?>
    <?php endif; ?>

    <form action="login.php" method="post">
        <div class="form-group">
            <label for="username">Kullanıcı Adı:</label>
            <input type="text" name="username" id="username" value="<?php echo htmlspecialchars($username ?? ''); ?>">
        </div>

        <div class="form-group">
            <label for="password">Şifre:</label>
            <input type="password" name="password" id="password">
        </div>

        <div class="form-group">
            <button type="submit" class="btn">Giriş Yap</button>
        </div>

        <p>Hesabınız yok mu? <a href="register.php">Kayıt Ol</a></p>
    </form>
</div>
</body>
</html>
