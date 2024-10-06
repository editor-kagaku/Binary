<?php
// 難読化前のPHPコード
// 'END'とシングルクォートで括っているのはコード中の変数を展開させないため
$code = <<<'END'
$password = "youcannotguessthispassword:)";

// bashの組み込みコマンドのreadコマンドを使って、パスワードをエコーバック
// しないようにしながらパスワード入力を受け付ける
print("Password: ");
$input = exec("bash -c 'read -s input; echo \$input'");

// 入力されたパスワードを比較した結果によってメッセージを変える
if (strcmp($input, $password) == 0) {
    print("\nおめでとうございます!正しいパスワードです。\n");
} else {
    print("\n残念!パスワードが違います。\n");
}

END;

// Deflateアルゴリズムでの圧縮(zlibヘッダ無し)
// ↓
// Base64エンコード
// ↓
// 文字列の順序の反転
// ↓
// ROT13
//
// の順番で操作してPHPコードを難読化し、デコードして実行する処理を追加して出力する
$obfuscated_code = str_rot13(strrev(base64_encode(gzdeflate($code))));
$output = <<<END
<?php
eval(gzinflate(base64_decode(strrev(str_rot13("$obfuscated_code")))))
?>

END;
print($output)
?>
