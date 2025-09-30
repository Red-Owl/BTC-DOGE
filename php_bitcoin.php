<?php

class Coin
{
    // Configuration options
    private $username;
    private $password;
    private $proto = 'http';
    private $host;
    private $port;
    private $url;
    private $CACertificate;
    private $wallet_passphrase = '';
    private $wallet_name = ''; // For Bitcoin Knots multi-wallet support

    // Information and debugging
    public $status;
    public $error;
    public $raw_response;
    public $response;

    private $id = 0;

    // Predefined ports for different coins
    private $coinPorts = [
        'bitcoin' => 8332,
        'bitcoingold' => 8338,
        'dogecoin' => 22555,
        'bitcoinknots' => 8332
    ];

    /**
     * Constructor
     * @param string $coin Name of the coin (bitcoin, bitcoingold, dogecoin, bitcoinknots)
     * @param string $username RPC username
     * @param string $password RPC password
     * @param string $host RPC host (default: localhost)
     * @param int $port RPC port (optional, uses default for coin if not specified)
     * @param string $url RPC URL (optional)
     * @param string $wallet_passphrase Wallet passphrase (optional)
     * @param string $wallet_name Wallet name for Bitcoin Knots (optional)
     */
    public function __construct($coin, $username, $password, $host = 'localhost', $port = null, $url = null, $wallet_passphrase = '', $wallet_name = '')
    {
        $this->username = $username;
        $this->password = $password;
        $this->host = $host;
        $this->port = $port ?? $this->coinPorts[strtolower($coin)] ?? 8332;
        $this->url = $url ?? ($wallet_name && strtolower($coin) === 'bitcoinknots' ? "wallet/$wallet_name" : '');
        $this->CACertificate = null;
        $this->wallet_passphrase = $wallet_passphrase;
        $this->wallet_name = $wallet_name;
    }

    /**
     * Set RPC credentials and configuration
     * @param array $config Configuration array with rpc_user, rpc_password, rpc_host, rpc_port, wallet_passphrase, wallet_name
     * @return bool
     */
    public function setCredentials($config)
    {
        if (empty($config['rpc_user']) || empty($config['rpc_password'])) {
            $this->error = 'Invalid or empty RPC credentials';
            error_log($this->error);
            return false;
        }
        $this->username = $config['rpc_user'];
        $this->password = $config['rpc_password'];
        $this->host = $config['rpc_host'] ?? 'localhost';
        $this->port = $config['rpc_port'] ?? $this->port;
        $this->wallet_passphrase = $config['wallet_passphrase'] ?? '';
        $this->wallet_name = $config['wallet_name'] ?? '';
        $this->url = $this->wallet_name && strtolower($this->coinPorts[array_key_exists($this->port, $this->coinPorts) ? array_search($this->port, $this->coinPorts) : 'bitcoin']) === 'bitcoinknots' ? "wallet/{$this->wallet_name}" : '';
        return true;
    }

    /**
     * Set an SSL certificate
     * @param string $certificate
     */
    public function setSSL($certificate)
    {
        $this->CACertificate = $certificate;
        $this->proto = 'https';
    }

    /**
     * Execute JSON-RPC request
     * @param string $method RPC method
     * @param array $params Parameters for the RPC method
     * @return mixed
     */
    private function request($method, $params = [])
    {
        $this->status = null;
        $this->error = null;
        $this->raw_response = null;
        $this->response = null;

        $request = [
            'method' => $method,
            'params' => $params,
            'id' => $this->id++,
            'jsonrpc' => '1.0'
        ];

        $auth = base64_encode("{$this->username}:{$this->password}");
        $url = "{$this->proto}://{$this->host}:{$this->port}/{$this->url}";

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            "Authorization: Basic $auth"
        ]);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($request));
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        if ($this->proto === 'https' && $this->CACertificate) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->CACertificate);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        }

        $this->raw_response = curl_exec($ch);
        $this->status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);

        if ($this->raw_response === false) {
            $this->error = $curl_error;
            error_log("Errore cURL: $curl_error");
            return ['error' => $curl_error];
        }

        $this->response = json_decode($this->raw_response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->error = 'JSON decode error: ' . json_last_error_msg();
            error_log($this->error);
            return ['error' => $this->error];
        }

        if (isset($this->response['error']) && $this->response['error'] !== null) {
            $this->error = $this->response['error']['message'] ?? 'Unknown error';
            error_log("Errore RPC per $method: " . json_encode($this->response['error']));
            return ['error' => $this->response['error']];
        }

        error_log("Risposta RPC per $method: " . json_encode($this->response));
        return $this->response['result'];
    }

    /**
     * Unlock wallet
     * @param int $timeout Unlock duration in seconds (default: 60)
     * @return bool
     */
    public function unlockWallet($timeout = 60)
    {
        if (empty($this->wallet_passphrase)) {
            $this->error = 'No wallet passphrase provided';
            error_log($this->error);
            return false;
        }

        error_log("Tentativo di sblocco con passphrase: " . $this->wallet_passphrase);
        $result = $this->request('walletpassphrase', [$this->wallet_passphrase, $timeout]);
        if (isset($result['error'])) {
            error_log("Fallito lo sblocco del portafoglio: " . json_encode($result));
            return false;
        }

        error_log("Portafoglio sbloccato con successo");
        return true;
    }

    /**
     * Get address for an account
     * @param string $account Account name
     * @return string|bool Address or false on failure
     */
    public function getAccountAddress($account)
    {
        if (!$this->unlockWallet()) {
            error_log("Fallito lo sblocco per getAccountAddress");
            return false;
        }
        $response = $this->request('getaccountaddress', [$account]);
        if (isset($response['error'])) {
            error_log("Errore in getaccountaddress: " . json_encode($response));
            return false;
        }
        return $response;
    }

    /**
     * Verify transaction confirmations
     * @param string $txid Transaction ID
     * @return int Number of confirmations or 0 on failure
     */
    public function verifyTransactionConfirmations($txid)
    {
        $response = $this->request('getrawtransaction', [$txid, true]);
        if (isset($response['error'])) {
            error_log("Errore in getrawtransaction: " . json_encode($response));
            return 0;
        }
        return isset($response['confirmations']) ? (int)$response['confirmations'] : 0;
    }

    /**
     * Get user payments for an account
     * @param string $account Account name
     * @param int $count Number of transactions to retrieve (default: 10)
     * @return array|bool Array of received transactions or false on failure
     */
    public function getUserPayments($account, $count = 10)
    {
        $response = $this->request('listtransactions', [$account, $count]);
        if (isset($response['error'])) {
            error_log("Errore in listtransactions: " . json_encode($response));
            return false;
        }
        $received = array_filter($response, function ($tx) {
            return $tx['category'] === 'receive';
        });
        return array_values($received);
    }

    /**
     * Send all available funds to an address
     * @param string $destination_address Destination address
     * @param float $fee Transaction fee (default: 0.00226 for Dogecoin)
     * @param float $dust_limit Minimum amount to send (default: 0.01)
     * @return string|bool Transaction ID or false on failure
     */
    public function sendAllToAddress($destination_address, $fee = 0.00226, $dust_limit = 0.01)
    {
        if (!$this->unlockWallet()) {
            error_log("Fallito lo sblocco per il trasferimento");
            return false;
        }

        $wallet_info = $this->request('getwalletinfo');
        if (isset($wallet_info['error']) || !isset($wallet_info['balance']) || $wallet_info['balance'] <= 0) {
            error_log("Nessun fondo disponibile o errore: " . json_encode($wallet_info));
            return false;
        }

        $balance = floatval($wallet_info['balance']);
        $amount_to_send = round($balance - $fee, 8);
        if ($amount_to_send <= 0 || $amount_to_send < $dust_limit) {
            error_log("Fondi insufficienti o importo troppo piccolo: $balance");
            return false;
        }

        error_log("Invio di $amount_to_send a $destination_address");
        $txid = $this->request('sendtoaddress', [$destination_address, $amount_to_send]);
        if (isset($txid['error'])) {
            error_log("Errore nel trasferimento: " . json_encode($txid));
            return false;
        }

        error_log("Trasferimento completato: " . $txid);
        return $txid;
    }

    /**
     * Get balance for an address
     * @param string $address Address to check
     * @param int $minconf Minimum confirmations (default: 6)
     * @return float|bool Balance or false on failure
     */
    public function getAddressBalance($address, $minconf = 6)
    {
        $response = $this->request('getreceivedbyaddress', [$address, $minconf]);
        if (isset($response['error'])) {
            error_log("Errore in getreceivedbyaddress: " . json_encode($response));
            return false;
        }
        return floatval($response);
    }

    /**
     * Get source address of a transaction
     * @param string $txid Transaction ID
     * @return string|null Source address or null if not found
     */
    public function getSourceAddress($txid)
    {
        $raw_tx = $this->request('getrawtransaction', [$txid, true]);
        if (isset($raw_tx['error'])) {
            error_log("Errore nel recupero della transazione $txid: " . json_encode($raw_tx));
            return null;
        }

        $vin = $raw_tx['vin'];
        foreach ($vin as $input) {
            if (isset($input['txid']) && isset($input['vout'])) {
                $prev_tx = $this->request('getrawtransaction', [$input['txid'], true]);
                if (!isset($prev_tx['error']) && isset($prev_tx['vout'][$input['vout']]['scriptPubKey']['addresses'])) {
                    return $prev_tx['vout'][$input['vout']]['scriptPubKey']['addresses'][0];
                }
            }
        }
        return null;
    }

    /**
     * Disconnect a peer
     * @param string $peer_address Peer address (e.g., '192.168.0.1:8333')
     * @return bool
     */
    public function disconnectPeer($peer_address)
    {
        $response = $this->request('disconnectnode', [$peer_address]);
        if (isset($response['error'])) {
            error_log("Errore in disconnectnode: " . json_encode($response));
            return false;
        }
        error_log("Peer $peer_address disconnesso con successo");
        return true;
    }

    /**
     * Reconnect to a peer
     * @param string $peer_address Peer address (e.g., '192.168.0.1:8333')
     * @return bool
     */
    public function reconnectPeer($peer_address)
    {
        $response = $this->request('addnode', [$peer_address, 'add']);
        if (isset($response['error'])) {
            error_log("Errore in addnode: " . json_encode($response));
            return false;
        }
        error_log("Tentativo di connessione a $peer_address avviato");
        return true;
    }

    /**
     * Get peer information
     * @return array|bool Peer info or false on failure
     */
    public function getPeers()
    {
        $response = $this->request('getpeerinfo');
        if (isset($response['error'])) {
            error_log("Errore in getpeerinfo: " . json_encode($response));
            return false;
        }
        return $response;
    }

    /**
     * Disconnect all peers
     * @return bool
     */
    public function disconnectAll()
    {
        $peers = $this->getPeers();
        if ($peers === false) {
            return false;
        }
        foreach ($peers as $peer) {
            $this->disconnectPeer($peer['addr']);
        }
        return true;
    }

    /**
     * Get local wallet info
     * @return array|bool Wallet info or false on failure
     */
    public function getLocalInfo()
    {
        if (!$this->unlockWallet()) {
            error_log("Fallito lo sblocco per getLocalInfo");
            return false;
        }
        $wallet_info = $this->request('getwalletinfo');
        if (isset($wallet_info['error'])) {
            error_log("Errore in getwalletinfo: " . json_encode($wallet_info));
            return false;
        }
        return $wallet_info;
    }

    /**
     * Add a custom node to the peer list
     * @param string $nodeAddress IP and port of the node (e.g., '192.168.0.1:8333')
     * @param string $command Action to perform ('add', 'remove', 'onetry')
     * @return array JSON response with result or error
     */
    public function addCustomNode($nodeAddress, $command = 'add')
    {
        if (!in_array($command, ['add', 'remove', 'onetry'])) {
            return ['error' => 'Invalid command. Use "add", "remove", or "onetry".'];
        }
        return $this->request('addnode', [$nodeAddress, $command]);
    }

    /**
     * Get transaction details by txid
     * @param string $txid Transaction ID
     * @return array JSON response with transaction details
     */
    public function getTransaction($txid)
    {
        return $this->request('getrawtransaction', [$txid, true]);
    }

    /**
     * Get block information by block hash
     * @param string $blockHash Block hash
     * @return array JSON response with block details
     */
    public function getBlock($blockHash)
    {
        return $this->request('getblock', [$blockHash]);
    }

    /**
     * Get transactions from a specific block
     * @param string $blockHash Block hash
     * @return array JSON response with transaction IDs and block info
     */
    public function getBlockTransactions($blockHash)
    {
        $block = $this->getBlock($blockHash);
        if (isset($block['error'])) {
            return $block;
        }
        $txids = $block['tx'] ?? [];
        return [
            'blockHash' => $blockHash,
            'blockHeight' => $block['height'],
            'txCount' => count($txids),
            'transactions' => $txids
        ];
    }

    /**
     * Get all transactions with details from a specific block
     * @param string|int $blockIdentifier Block hash or block height
     * @return array JSON response with detailed transactions
     */
    public function getAllBlockTransactions($blockIdentifier)
    {
        if (is_numeric($blockIdentifier)) {
            $blockHash = $this->request('getblockhash', [(int)$blockIdentifier]);
            if (isset($blockHash['error'])) {
                return $blockHash;
            }
        } else {
            $blockHash = $blockIdentifier;
        }

        $block = $this->getBlock($blockHash);
        if (isset($block['error'])) {
            return $block;
        }

        $transactions = [];
        $txids = $block['tx'] ?? [];
        foreach ($txids as $txid) {
            $txDetails = $this->getTransaction($txid);
            if (!isset($txDetails['error'])) {
                $transactions[] = [
                    'txid' => $txid,
                    'details' => $txDetails
                ];
            }
        }

        return [
            'blockHash' => $blockHash,
            'blockHeight' => $block['height'],
            'transactions' => $transactions
        ];
    }

    /**
     * Get a paginated list of blocks
     * @param int $page Page number (1-based)
     * @param int $perPage Number of blocks per page
     * @return array JSON response with block list and pagination info
     */
    public function getBlockList($page = 1, $perPage = 10)
    {
        if ($page < 1 || $perPage < 1) {
            return ['error' => 'Invalid page or perPage parameters'];
        }

        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }

        $totalBlocks = $blockchainInfo['blocks'];
        $startHeight = ($page - 1) * $perPage;
        $endHeight = $startHeight + $perPage - 1;
        $endHeight = min($endHeight, $totalBlocks);

        if ($startHeight > $totalBlocks) {
            return ['error' => 'Page out of range'];
        }

        $blocks = [];
        for ($height = $startHeight; $height <= $endHeight; $height++) {
            $blockHash = $this->request('getblockhash', [$height]);
            if (isset($blockHash['error'])) {
                continue;
            }

            $block = $this->getBlock($blockHash);
            if (isset($block['error'])) {
                continue;
            }

            $blocks[] = [
                'hash' => $block['hash'],
                'height' => $block['height'],
                'time' => $block['time'],
                'txCount' => count($block['tx'] ?? []),
                'size' => $block['size'],
                'difficulty' => $block['difficulty'],
                'previousblockhash' => $block['previousblockhash'] ?? null,
                'nextblockhash' => $block['nextblockhash'] ?? null
            ];
        }

        return [
            'blocks' => $blocks,
            'page' => $page,
            'perPage' => $perPage,
            'totalBlocks' => $totalBlocks,
            'totalPages' => ceil($totalBlocks / $perPage)
        ];
    }

    /**
     * Get block list starting from a specific height
     * @param int $startHeight Starting block height
     * @param int $perPage Number of blocks per page
     * @return array JSON response with block list and pagination info
     */
    public function getBlockListFrom($startHeight = 0, $perPage = 10)
    {
        if ($startHeight < 0 || $perPage < 1) {
            return ['error' => 'Invalid startHeight or perPage parameters'];
        }

        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }

        $totalBlocks = $blockchainInfo['blocks'];
        $endHeight = $startHeight + $perPage - 1;
        $endHeight = min($endHeight, $totalBlocks);

        if ($startHeight > $totalBlocks) {
            return ['error' => 'Start height out of range'];
        }

        $blocks = [];
        for ($height = $startHeight; $height <= $endHeight; $height++) {
            $blockHash = $this->request('getblockhash', [$height]);
            if (isset($blockHash['error'])) {
                continue;
            }

            $block = $this->getBlock($blockHash);
            if (isset($block['error'])) {
                continue;
            }

            $blocks[] = [
                'hash' => $block['hash'],
                'height' => $block['height'],
                'time' => $block['time'],
                'txCount' => count($block['tx'] ?? []),
                'size' => $block['size'],
                'difficulty' => $block['difficulty'],
                'previousblockhash' => $block['previousblockhash'] ?? null,
                'nextblockhash' => $block['nextblockhash'] ?? null
            ];
        }

        return [
            'blocks' => $blocks,
            'startHeight' => $startHeight,
            'perPage' => $perPage,
            'totalBlocks' => $totalBlocks,
            'totalPages' => ceil($totalBlocks / $perPage)
        ];
    }

    /**
     * Get block hash by block height
     * @param int $height Block height
     * @return array JSON response with block hash
     */
    public function getBlockHashByHeight($height)
    {
        if (!is_numeric($height) || $height < 0) {
            return ['error' => 'Invalid block height'];
        }

        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }

        if ($height > $blockchainInfo['blocks']) {
            return ['error' => 'Block height out of range'];
        }

        $blockHash = $this->request('getblockhash', [(int)$height]);
        if (isset($blockHash['error'])) {
            return $blockHash;
        }

        return [
            'height' => (int)$height,
            'blockHash' => $blockHash
        ];
    }

    /**
     * Get block height by block hash
     * @param string $blockHash Block hash
     * @return array JSON response with block height
     */
    public function getBlockHeightByHash($blockHash)
    {
        if (!is_string($blockHash) || !preg_match('/^[0-9a-fA-F]{64}$/', $blockHash)) {
            return ['error' => 'Invalid block hash'];
        }

        $block = $this->getBlock($blockHash);
        if (isset($block['error'])) {
            return $block;
        }

        return [
            'blockHash' => $blockHash,
            'height' => $block['height']
        ];
    }

    /**
     * Get total amounts sent and received in a block
     * @param string|int $blockIdentifier Block hash or block height
     * @return array JSON response with total sent, received, and fees
     */
    public function getBlockTotalAmounts($blockIdentifier)
    {
        if (is_numeric($blockIdentifier)) {
            $blockHash = $this->request('getblockhash', [(int)$blockIdentifier]);
            if (isset($blockHash['error'])) {
                return $blockHash;
            }
        } else {
            $blockHash = $blockIdentifier;
        }

        $block = $this->getBlock($blockHash);
        if (isset($block['error'])) {
            return $block;
        }

        $totalSent = 0.0;
        $totalReceived = 0.0;
        $totalFees = 0.0;
        $txids = $block['tx'] ?? [];

        foreach ($txids as $index => $txid) {
            $txDetails = $this->getTransaction($txid);
            if (isset($txDetails['error'])) {
                continue;
            }

            $txReceived = 0.0;
            foreach ($txDetails['vout'] as $vout) {
                if (isset($vout['value'])) {
                    $txReceived += $vout['value'];
                }
            }
            $totalReceived += $txReceived;

            $txSent = 0.0;
            if ($index > 0) {
                foreach ($txDetails['vin'] as $vin) {
                    if (isset($vin['txid']) && isset($vin['vout'])) {
                        $prevTx = $this->getTransaction($vin['txid']);
                        if (!isset($prevTx['error'])) {
                            $txSent += $prevTx['vout'][$vin['vout']]['value'] ?? 0.0;
                        }
                    }
                }
            }

            $totalSent += $txSent;
            $totalFees += ($txSent - $txReceived);
        }

        return [
            'blockHash' => $blockHash,
            'blockHeight' => $block['height'],
            'totalSent' => $totalSent,
            'totalReceived' => $totalReceived,
            'totalFees' => $totalFees,
            'txCount' => count($txids)
        ];
    }

    /**
     * Get wallet information including balance, UTXOs, and transactions
     * @param array $addresses List of wallet addresses
     * @param bool $includeTransactions Whether to include transaction details
     * @param string|null $blockHash Optional block hash to start transaction listing
     * @return array JSON response with wallet balance, UTXOs, and transactions
     */
    public function getWalletInfo($addresses, $includeTransactions = false, $blockHash = null)
    {
        if (!is_array($addresses) || empty($addresses)) {
            return ['error' => 'Invalid or empty address list'];
        }

        if (!$this->unlockWallet()) {
            error_log("Fallito lo sblocco per getWalletInfo");
            return ['error' => 'Failed to unlock wallet'];
        }

        $utxos = $this->request('listunspent', [0, 9999999, $addresses]);
        if (isset($utxos['error'])) {
            return $utxos;
        }

        $totalBalance = 0.0;
        foreach ($utxos as $utxo) {
            $totalBalance += $utxo['amount'] ?? 0.0;
        }

        $result = [
            'addresses' => $addresses,
            'totalBalance' => $totalBalance,
            'utxos' => $utxos,
        ];

        if ($includeTransactions) {
            $transactions = [];
            foreach ($addresses as $address) {
                $txs = $this->getTransactionsByAddress($address, $blockHash);
                if (!isset($txs['error'])) {
                    $transactions = array_merge($transactions, $txs);
                }
            }
            $result['transactions'] = $transactions;
        }

        return $result;
    }

    /**
     * Check if addressindex is enabled
     * @param string $testAddress Address to test (optional, default is a dummy address)
     * @return array JSON response with addressIndexEnabled status
     */
    public function isAddressIndexEnabled($testAddress = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    {
        $result = $this->request('getaddresstxids', [['addresses' => [$testAddress]]]);
        if (isset($result['error']) && strpos($result['error']['message'], 'method not found') !== false) {
            return ['addressIndexEnabled' => false];
        }
        return ['addressIndexEnabled' => true];
    }

    /**
     * Get blockchain info
     * @return array JSON response with blockchain info
     */
    public function getBlockchainInfo()
    {
        $blockList = $this->request('getblockchaininfo');
        // return json_encode(array('blocks' => $blockList['blocks']),JSON_PRETTY_PRINT);
        return json_encode($blockList,JSON_PRETTY_PRINT);
    }

    /**
     * Get transactions for a specific address using listsinceblock
     * @param string $address Address to filter transactions
     * @param string $blockHash Optional block hash to start from
     * @return array JSON response with filtered transactions
     */
    public function getTransactionsByAddress($address, $blockHash = null)
    {
        $params = [$blockHash ?? '', 1, true];
        $result = $this->request('listsinceblock', $params);
        if (isset($result['error'])) {
            return $result;
        }

        $filteredTransactions = [];
        foreach ($result['transactions'] as $tx) {
            if (isset($tx['address']) && $tx['address'] === $address) {
                $filteredTransactions[] = $tx;
            } elseif (isset($tx['category']) && $tx['category'] === 'receive') {
                $txDetails = $this->getTransaction($tx['txid']);
                if (isset($txDetails['vout'])) {
                    foreach ($txDetails['vout'] as $vout) {
                        if (isset($vout['scriptPubKey']['addresses']) && in_array($address, $vout['scriptPubKey']['addresses'])) {
                            $filteredTransactions[] = array_merge($tx, ['details' => $txDetails]);
                            break;
                        }
                    }
                }
            }
        }

        return $filteredTransactions;
    }

    /**
     * Check for received and sent payments for a wallet's addresses
     * @param array $addresses List of wallet addresses
     * @param string|null $blockHash Optional block hash to start from
     * @param int $minConfirmations Minimum number of confirmations (default: 1)
     * @param string $movement Type of transactions to include ('receive', 'send', 'all') (default: 'receive')
     * @return array JSON response with received and sent payments details
     */
    public function checkWalletPayments($addresses, $blockHash = null, $minConfirmations = 1, $movement = 'receive')
    {
        if (!is_array($addresses) || empty($addresses)) {
            return ['error' => 'Invalid or empty address list'];
        }

        if (!in_array($movement, ['receive', 'send', 'all'])) {
            return ['error' => 'Invalid movement parameter. Use "receive", "send", or "all".'];
        }

        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }

        $currentHeight = $blockchainInfo['blocks'];
        $params = [$blockHash ?? '', $minConfirmations, true];
        $result = $this->request('listsinceblock', $params);
        if (isset($result['error'])) {
            return $result;
        }

        $receivedPayments = [];
        $sentPayments = [];
        foreach ($result['transactions'] as $tx) {
            if (!in_array($tx['address'], $addresses)) {
                continue;
            }

            $txDetails = $this->getTransaction($tx['txid']);
            if (isset($txDetails['error'])) {
                continue;
            }

            if ($tx['category'] === 'receive' && ($movement === 'receive' || $movement === 'all')) {
                $senderAddresses = [];
                foreach ($txDetails['vin'] as $vin) {
                    if (isset($vin['txid']) && isset($vin['vout'])) {
                        $prevTx = $this->getTransaction($vin['txid']);
                        if (!isset($prevTx['error']) && isset($prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses'])) {
                            $senderAddresses = array_merge($senderAddresses, $prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses']);
                        }
                    }
                }

                $receivedPayments[] = [
                    'txid' => $tx['txid'],
                    'address' => $tx['address'],
                    'amount' => $tx['amount'],
                    'senderAddresses' => array_unique($senderAddresses),
                    'blockHeight' => $txDetails['blockheight'] ?? null,
                    'confirmations' => $tx['confirmations'],
                    'time' => $tx['time'],
                    'details' => $txDetails
                ];
            } elseif ($tx['category'] === 'send' && ($movement === 'send' || $movement === 'all')) {
                $recipientAddresses = [];
                foreach ($txDetails['vout'] as $vout) {
                    if (isset($vout['scriptPubKey']['addresses'])) {
                        $recipientAddresses = array_merge($recipientAddresses, $vout['scriptPubKey']['addresses']);
                    }
                }

                $sentPayments[] = [
                    'txid' => $tx['txid'],
                    'address' => $tx['address'],
                    'amount' => abs($tx['amount']),
                    'recipientAddresses' => array_unique($recipientAddresses),
                    'blockHeight' => $txDetails['blockheight'] ?? null,
                    'confirmations' => $tx['confirmations'],
                    'time' => $tx['time'],
                    'details' => $txDetails
                ];
            }
        }

        return [
            'addresses' => $addresses,
            'receivedPayments' => $receivedPayments,
            'sentPayments' => $sentPayments,
            'currentHeight' => $currentHeight
        ];
    }

    /**
     * Check for received and sent payments using addressindex
     * @param array $addresses List of wallet addresses
     * @param string|null $blockHash Optional block hash to start from
     * @param int $minConfirmations Minimum number of confirmations (default: 1)
     * @return array JSON response with received and sent payments details
     */
    public function checkWalletPaymentsById($addresses, $blockHash = null, $minConfirmations = 1)
    {
        if (!is_array($addresses) || empty($addresses)) {
            return ['error' => 'Invalid or empty address list'];
        }

        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }

        $currentHeight = $blockchainInfo['blocks'];

        $indexStatus = $this->isAddressIndexEnabled();
        if (!$indexStatus['addressIndexEnabled']) {
            return ['error' => 'Address index not enabled'];
        }

        $receivedPayments = [];
        $sentPayments = [];
        foreach ($addresses as $address) {
            $txids = $this->request('getaddresstxids', [['addresses' => [$address]]]);
            if (isset($txids['error'])) {
                continue;
            }
            foreach ($txids as $txid) {
                $txDetails = $this->getTransaction($txid);
                if (isset($txDetails['error']) || !isset($txDetails['vout']) || !isset($txDetails['vin'])) {
                    continue;
                }

                $confirmations = isset($txDetails['blockheight']) ? $currentHeight - $txDetails['blockheight'] + 1 : 0;
                if ($confirmations < $minConfirmations) {
                    continue;
                }

                $receivedAmount = 0.0;
                foreach ($txDetails['vout'] as $vout) {
                    if (isset($vout['scriptPubKey']['addresses']) && in_array($address, $vout['scriptPubKey']['addresses'])) {
                        $receivedAmount += $vout['value'];
                    }
                }
                if ($receivedAmount > 0) {
                    $senderAddresses = [];
                    foreach ($txDetails['vin'] as $vin) {
                        if (isset($vin['txid']) && isset($vin['vout'])) {
                            $prevTx = $this->getTransaction($vin['txid']);
                            if (!isset($prevTx['error']) && isset($prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses'])) {
                                $senderAddresses = array_merge($senderAddresses, $prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses']);
                            }
                        }
                    }
                    $receivedPayments[] = [
                        'txid' => $txid,
                        'address' => $address,
                        'amount' => $receivedAmount,
                        'senderAddresses' => array_unique($senderAddresses),
                        'blockHeight' => $txDetails['blockheight'] ?? null,
                        'confirmations' => $confirmations,
                        'time' => $txDetails['time'] ?? null,
                        'details' => $txDetails
                    ];
                }

                $sentAmount = 0.0;
                $recipientAddresses = [];
                foreach ($txDetails['vin'] as $vin) {
                    if (isset($vin['txid']) && isset($vin['vout'])) {
                        $prevTx = $this->getTransaction($vin['txid']);
                        if (!isset($prevTx['error']) && isset($prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses']) && in_array($address, $prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses'])) {
                            $sentAmount += $prevTx['vout'][$vin['vout']]['value'];
                        }
                    }
                }
                foreach ($txDetails['vout'] as $vout) {
                    if (isset($vout['scriptPubKey']['addresses'])) {
                        $recipientAddresses = array_merge($recipientAddresses, $vout['scriptPubKey']['addresses']);
                    }
                }
                if ($sentAmount > 0) {
                    $sentPayments[] = [
                        'txid' => $txid,
                        'address' => $address,
                        'amount' => $sentAmount,
                        'recipientAddresses' => array_unique($recipientAddresses),
                        'blockHeight' => $txDetails['blockheight'] ?? null,
                        'confirmations' => $confirmations,
                        'time' => $txDetails['time'] ?? null,
                        'details' => $txDetails
                    ];
                }
            }
        }
        return [
            'addresses' => $addresses,
            'receivedPayments' => $receivedPayments,
            'sentPayments' => $sentPayments,
            'currentHeight' => $currentHeight
        ];
    }

    /**
     * Track wallet balance and historical balance changes
     * @param array $addresses List of wallet addresses
     * @param string|null $blockHash Optional block hash to start from
     * @param int $minConfirmations Minimum number of confirmations (default: 1)
     * @param int|null $startHeight Start block height for filtering (optional)
     * @param int|null $endHeight End block height for filtering (optional)
     * @param int|null $startTimestamp Start timestamp for filtering (optional)
     * @param int|null $endTimestamp End timestamp for filtering (optional)
     * @param string $movement Type of transactions to include ('receive', 'send', 'all') (default: 'all')
     * @param int|null $maxTransactions Maximum number of transactions to process (optional)
     * @return array JSON response with current balance and transaction history
     */
    public function trackWalletBalance($addresses, $blockHash = null, $minConfirmations = 1, $startHeight = null, $endHeight = null, $startTimestamp = null, $endTimestamp = null, $movement = 'all', $maxTransactions = null)
    {
        if (!is_array($addresses) || empty($addresses)) {
            return ['error' => 'Invalid or empty address list'];
        }

        if (!in_array($movement, ['receive', 'send', 'all'])) {
            return ['error' => 'Invalid movement parameter. Use "receive", "send", or "all".'];
        }

        if (!$this->unlockWallet()) {
            error_log("Fallito lo sblocco per trackWalletBalance");
            return ['error' => 'Failed to unlock wallet'];
        }

        $walletInfo = $this->getWalletInfo($addresses);
        if (isset($walletInfo['error'])) {
            return $walletInfo;
        }

        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }
        $currentHeight = $blockchainInfo['blocks'];

        $indexStatus = $this->isAddressIndexEnabled();
        $useAddressIndex = $indexStatus['addressIndexEnabled'];

        $payments = $useAddressIndex
            ? $this->checkWalletPaymentsById($addresses, $blockHash, $minConfirmations)
            : $this->checkWalletPayments($addresses, $blockHash, $minConfirmations, $movement);
        if (isset($payments['error'])) {
            return $payments;
        }

        $allPayments = array_merge(
            $movement === 'send' ? [] : $payments['receivedPayments'],
            $movement === 'receive' ? [] : $payments['sentPayments']
        );
        $filteredPayments = array_filter($allPayments, function ($tx) use ($startHeight, $endHeight, $startTimestamp, $endTimestamp) {
            $blockHeight = $tx['blockHeight'] ?? null;
            $time = $tx['time'] ?? null;
            return (
                ($startHeight === null || ($blockHeight !== null && $blockHeight >= $startHeight)) &&
                ($endHeight === null || ($blockHeight !== null && $blockHeight <= $endHeight)) &&
                ($startTimestamp === null || ($time !== null && $time >= $startTimestamp)) &&
                ($endTimestamp === null || ($time !== null && $time <= $endTimestamp))
            );
        });

        usort($filteredPayments, function ($a, $b) {
            $timeA = $a['time'] ?? PHP_INT_MAX;
            $timeB = $b['time'] ?? PHP_INT_MAX;
            return $timeA <=> $timeB;
        });

        if ($maxTransactions !== null) {
            $filteredPayments = array_slice($filteredPayments, 0, $maxTransactions);
        }

        $balanceHistory = [];
        $currentBalance = $walletInfo['totalBalance'];
        $balance = 0.0;
        foreach ($filteredPayments as $tx) {
            $amount = isset($tx['senderAddresses']) ? $tx['amount'] : -$tx['amount'];
            $balance += $amount;
            $balanceHistory[] = [
                'txid' => $tx['txid'],
                'type' => isset($tx['senderAddresses']) ? 'receive' : 'send',
                'amount' => $tx['amount'],
                'balanceAfter' => $balance,
                'blockHeight' => $tx['blockHeight'] ?? null,
                'time' => $tx['time'] ?? null,
                'addressesInvolved' => isset($tx['senderAddresses']) ? $tx['senderAddresses'] : $tx['recipientAddresses']
            ];
        }

        return [
            'addresses' => $addresses,
            'currentBalance' => $currentBalance,
            'currentHeight' => $currentHeight,
            'balanceHistory' => $balanceHistory,
            'utxos' => $walletInfo['utxos']
        ];
    }

    /**
     * Scan blocks for transactions involving a specific address
     * @param string $address Address to filter transactions
     * @param int $startHeight Start block height
     * @param int $endHeight End block height
     * @return array JSON response with filtered transactions
     */
    public function scanBlocksForAddress($address, $startHeight, $endHeight)
    {
        $transactions = [];
        $blockchainInfo = $this->getBlockchainInfo();

        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }

        $currentHeight = $blockchainInfo['blocks'];
        $startHeight = max(0, $startHeight);
        $endHeight = min($endHeight, $currentHeight);

        for ($height = $startHeight; $height <= $endHeight; $height++) {
            $blockHash = $this->request('getblockhash', [$height]);
            if (isset($blockHash['error'])) {
                continue;
            }

            $block = $this->getBlock($blockHash);
            if (isset($block['error'])) {
                continue;
            }

            $txids = $block['tx'] ?? [];
            foreach ($txids as $txid) {
                $txDetails = $this->getTransaction($txid);
                if (isset($txDetails['vout'])) {
                    foreach ($txDetails['vout'] as $vout) {
                        if (isset($vout['scriptPubKey']['addresses']) && in_array($address, $vout['scriptPubKey']['addresses'])) {
                            $transactions[] = [
                                'txid' => $txid,
                                'blockheight' => $height,
                                'details' => $txDetails
                            ];
                            break;
                        }
                    }
                }
            }
        }

        return $transactions;
    }

    /**
     * Trace the flow of funds from a source address to a destination address
     * @param string $sourceAddress Source address
     * @param string $destinationAddress Destination address
     * @param int $maxHops Maximum number of intermediate addresses to follow
     * @param int $startHeight Start block height for scanning
     * @param int $endHeight End block height for scanning
     * @return array JSON response with transaction flow
     */
    public function traceTransactionFlow($sourceAddress, $destinationAddress, $maxHops = 5, $startHeight = 0, $endHeight = null)
    {
        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }

        $endHeight = $endHeight ?? $blockchainInfo['blocks'];
        $endHeight = min($endHeight, $blockchainInfo['blocks']);
        $startHeight = max(0, $startHeight);

        $visitedTxids = [];
        $flow = [];
        $queue = [];

        $initialTxs = $this->scanBlocksForAddress($sourceAddress, $startHeight, $endHeight);
        if (empty($initialTxs)) {
            return ['error' => 'No transactions found for source address'];
        }

        foreach ($initialTxs as $tx) {
            $queue[] = [
                'txid' => $tx['txid'],
                'details' => $tx['details'],
                'path' => [$sourceAddress],
                'hops' => 0
            ];
        }

        while (!empty($queue)) {
            $current = array_shift($queue);
            $txid = $current['txid'];
            $txDetails = $current['details'];
            $currentPath = $current['path'];
            $hops = $current['hops'];

            if ($hops >= $maxHops) {
                continue;
            }

            if (in_array($txid, $visitedTxids)) {
                continue;
            }

            $visitedTxids[] = $txid;

            $outputs = $txDetails['vout'] ?? [];
            foreach ($outputs as $vout) {
                if (!isset($vout['scriptPubKey']['addresses'])) {
                    continue;
                }

                foreach ($vout['scriptPubKey']['addresses'] as $address) {
                    $newPath = array_merge($currentPath, [$address]);
                    $flow[] = [
                        'txid' => $txid,
                        'from' => $currentPath[count($currentPath) - 1],
                        'to' => $address,
                        'value' => $vout['value'],
                        'path' => $newPath,
                        'hops' => $hops + 1
                    ];

                    if ($address === $destinationAddress) {
                        continue;
                    }

                    $nextTxs = $this->findSpendingTransactions($txid, $vout['n']);
                    foreach ($nextTxs as $nextTx) {
                        if (!in_array($nextTx['txid'], $visitedTxids)) {
                            $queue[] = [
                                'txid' => $nextTx['txid'],
                                'details' => $nextTx['details'],
                                'path' => $newPath,
                                'hops' => $hops + 1
                            ];
                        }
                    }
                }
            }
        }

        $relevantFlow = array_filter($flow, function ($entry) use ($destinationAddress) {
            return end($entry['path']) === $destinationAddress;
        });

        return array_values($relevantFlow) ?: ['error' => 'No path found to destination address'];
    }

    /**
     * Find transactions that spend a specific output
     * @param string $txid Transaction ID
     * @param int $voutIndex Output index
     * @return array Transactions that spend the output
     */
    private function findSpendingTransactions($txid, $voutIndex)
    {
        $spendingTxs = [];
        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $spendingTxs;
        }

        $currentHeight = $blockchainInfo['blocks'];
        $txDetails = $this->getTransaction($txid);
        if (isset($txDetails['error'])) {
            return $spendingTxs;
        }

        $blockHash = $txDetails['blockhash'] ?? null;
        if (!$blockHash) {
            return $spendingTxs;
        }

        $block = $this->getBlock($blockHash);
        if (isset($block['error'])) {
            return $spendingTxs;
        }

        $startHeight = $block['height'];

        for ($height = $startHeight; $height <= $currentHeight; $height++) {
            $blockHash = $this->request('getblockhash', [$height]);
            if (isset($blockHash['error'])) {
                continue;
            }

            $block = $this->getBlock($blockHash);
            if (isset($block['error'])) {
                continue;
            }

            foreach ($block['tx'] as $nextTxid) {
                $nextTxDetails = $this->getTransaction($nextTxid);
                if (isset($nextTxDetails['error'])) {
                    continue;
                }

                foreach ($nextTxDetails['vin'] as $vin) {
                    if (isset($vin['txid']) && $vin['txid'] === $txid && $vin['vout'] === $voutIndex) {
                        $spendingTxs[] = [
                            'txid' => $nextTxid,
                            'details' => $nextTxDetails
                        ];
                    }
                }
            }
        }

        return $spendingTxs;
    }
}