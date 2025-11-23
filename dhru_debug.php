<?php
// dhru_debug.php
date_default_timezone_set('UTC');

$log = date('c') . "\n";
$log .= "POST:\n" . print_r($_POST, true) . "\n";
$log .= "GET:\n" . print_r($_GET, true) . "\n";
$log .= "RAW:\n" . file_get_contents('php://input') . "\n";
$log .= "-----------------------------\n";

file_put_contents(__DIR__ . '/dhru_debug.log', $log, FILE_APPEND);

// Respuesta mínima en formato DHRU para que no se queje
header('Content-Type: application/json');
echo json_encode([
    "SUCCESS" => [[ "MESSAGE" => "DEBUG OK" ]],
    "apiversion" => "5.2"
]);
