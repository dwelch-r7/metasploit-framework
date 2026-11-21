<?php
$source = file_get_contents('/opt/meterpreter.php');
$marker = '# Parse configuration from TLV config block';
if (substr_count($source, $marker) !== 1) {
    throw new RuntimeException('Cannot identify the original runtime boundary');
}
eval(explode($marker, $source, 2)[0]);

function run_case($fragmented) {
    $listener = stream_socket_server("tcp://127.0.0.1:0", $errno, $message);
    if ($listener === false) {
        throw new RuntimeException("Cannot create loopback TCP listener: " . $message);
    }
    $peer = stream_socket_client("tcp://" . stream_socket_get_name($listener, false), $errno, $message, 2);
    $server = stream_socket_accept($listener, 2);
    fclose($listener);
    if ($peer === false || $server === false) {
        throw new RuntimeException("Cannot create loopback TCP connection");
    }
    $GLOBALS['readers'] = [];
    $GLOBALS['resource_type_map'] = [];
    $GLOBALS['AES_KEY'] = null;
    $GLOBALS['AES_ENABLED'] = false;
    $GLOBALS['UUID'] = str_repeat("\0", 16);
    $GLOBALS['SESSION_GUID'] = str_repeat("\0", 16);
    $GLOBALS['running'] = true;
    $GLOBALS['session_expiry_end'] = time() + 5;
    $GLOBALS['current_transport_idx'] = 0;
    $GLOBALS['next_transport_idx'] = null;
    $GLOBALS['msgsock'] = $server;
    $GLOBALS['msgsock_type'] = 'stream';
    $GLOBALS['_msgsock_consumed'] = false;
    $GLOBALS['transport_list'] = [['type' => 'tcp']];
    $transport = &$GLOBALS['transport_list'][0];
    if (!activate_transport($transport)) {
        throw new RuntimeException('Original transport activation failed');
    }
    $empty = read($server, 8);
    $open = !feof($server);
    $request = pack('N', PACKET_TYPE_REQUEST);
    packet_add_tlv($request, create_tlv(TLV_TYPE_COMMAND_ID, COMMAND_ID_CORE_SHUTDOWN));
    packet_add_tlv($request, create_tlv(TLV_TYPE_REQUEST_ID, 'native-stream-proof'));
    $request = pack('N', strlen($request) + 4) . $request;
    $key = 'abcd';
    $wire = $key . xor_bytes($key, str_repeat("\0", 16) . pack('N', ENC_NONE) . $request);
    $bytes = $fragmented ? substr($wire, 0, 32) : $wire;
    if (fwrite($peer, $bytes) !== strlen($bytes)) {
        throw new RuntimeException('Native peer could not send the packet');
    }
    $result = dispatch_tcp($transport);
    $row = ['fragmented' => $fragmented, 'complete_packet_bytes' => strlen($wire), 'sent_bytes' => strlen($bytes),
            'empty_read_before_send' => $empty === '', 'peer_open_before_send' => $open,
            'dispatch_result' => $result, 'shutdown_processed' => !$GLOBALS['running'],
            'server_still_open' => is_resource($server)];
    fclose($peer);
    if (is_resource($server)) {
        fclose($server);
    }
    return $row;
}

$whole = run_case(false);
$split = run_case(true);
if ($whole['dispatch_result'] !== DISPATCH_EXIT || !$whole['shutdown_processed'] ||
    $split['dispatch_result'] !== DISPATCH_RETIRE || $split['shutdown_processed'] ||
    !$split['empty_read_before_send'] || !$split['peer_open_before_send'] || $split['server_still_open']) {
    throw new RuntimeException('Original transport did not reproduce the expected contrast: ' . json_encode([$whole, $split]));
}
echo json_encode(['source_sha256' => hash('sha256', $source), 'definitions_are_original' => true, 'transport' => 'loopback-tcp',
                  'whole' => $whole, 'split' => $split, 'premature_retirement_confirmed' => true], JSON_THROW_ON_ERROR);
