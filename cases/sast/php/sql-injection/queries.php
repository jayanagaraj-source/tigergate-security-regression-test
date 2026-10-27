<?php
// SQL injection cases for TG-TAINT-PHP-SQL-INJECTION. Fixtures only; no database is contacted.

function byId($conn)
{
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']); // PHP-SQL-TP-001
}

function byName()
{
    $pdo = new PDO('sqlite::memory:');
    return $pdo->query("SELECT * FROM users WHERE name = '" . $_POST['name'] . "'"); // PHP-SQL-TP-002
}

function search(PDO $db)
{
    return $db->query("SELECT * FROM products WHERE title LIKE '%" . $_GET['q'] . "%'"); // PHP-SQL-TP-003
}

function remove()
{
    $mysqli = new mysqli('localhost', 'app', '', 'app');
    return $mysqli->query("DELETE FROM sessions WHERE id = " . $_REQUEST['sid']); // PHP-SQL-TP-004
}

class ReportRepository
{
    private $db;

    public function sorted()
    {
        return $this->db->query("SELECT * FROM reports ORDER BY " . $_GET['sort']); // PHP-SQL-TP-005
    }
}

function rename(PDO $pdo)
{
    return $pdo->exec("UPDATE users SET name = '" . $_POST['name'] . "' WHERE id = 1"); // PHP-SQL-TP-006
}

function doctrine(\Doctrine\DBAL\Connection $conn)
{
    return $conn->query("SELECT * FROM prefs WHERE theme = '" . $_COOKIE['theme'] . "'"); // PHP-SQL-TP-007
}

function nullable(?PDO $db)
{
    return $db->query("SELECT * FROM orders WHERE status = '" . $_GET['status'] . "'"); // PHP-SQL-TP-008
}

function viaVariable($link)
{
    $sql = "SELECT * FROM audit WHERE actor = '" . $_GET['actor'] . "'"; // PHP-SQL-TP-009
    return mysqli_query($link, $sql); // PHP-SQL-TP-009
}

function interpolated($link)
{
    return mysqli_query($link, "SELECT * FROM tags WHERE name = '{$_GET['tag']}'"); // PHP-SQL-TP-010
}

function prepared(PDO $pdo)
{
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_GET['id']]); // PHP-SQL-TN-001
    return $stmt->fetchAll();
}

function countUsers($conn)
{
    return mysqli_query($conn, "SELECT COUNT(*) FROM users"); // PHP-SQL-TN-002
}

function boundMysqli($conn)
{
    $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE email = ?");
    mysqli_stmt_bind_param($stmt, "s", $_POST['email']); // PHP-SQL-TN-003
    return mysqli_stmt_execute($stmt);
}

function fixedTable(PDO $pdo)
{
    $table = 'audit_log';
    return $pdo->query("SELECT * FROM " . $table . " ORDER BY id DESC"); // PHP-SQL-TN-004
}

function castToInt(PDO $pdo)
{
    return $pdo->query("SELECT * FROM users WHERE id = " . (int) $_GET['id']); // PHP-SQL-TN-005
}
