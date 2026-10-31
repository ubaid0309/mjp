<?php
// ByteMart legacy profile page - DEMO DATA, intentionally vulnerable. Do not deploy.
$conn = mysqli_connect("localhost", "bytemart", getenv("DB_PASS"), "bytemart");

$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT name, email FROM customers WHERE id = " . $id);
$row = mysqli_fetch_assoc($result);

echo "<h1>Welcome back, " . $_GET['name'] . "</h1>";

include $_GET['page'] . ".php";

if (isset($_FILES['photo'])) {
    move_uploaded_file($_FILES['photo']['tmp_name'], "uploads/" . $_FILES['photo']['name']);
}

$prefs = unserialize($_COOKIE['prefs']);
$hash = md5($_POST['password']);
