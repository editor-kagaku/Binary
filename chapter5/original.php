<?php
$password = "youcannotguessthispassword:)";

// bashの組み込みコマンドのreadコマンドを使って、パスワードをエコーバック
// しないようにしながらパスワード入力を受け付ける
print("Password: ");
$input = exec("/bin/bash -c 'read -s input; echo \$input'");

// 入力されたパスワードを比較した結果によってメッセージを変える
if (strcmp($input, $password) == 0) {
    print("\nおめでとうございます!正しいパスワードです。\n");
} else {
    print("\n残念!パスワードが違います。\n");
}
?>
