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
        'bitcoinknots' => 8332,
        'litecoin' => 9332
    ];

    // Predefined prefixes for database tables
    private $coinPrefixes = [
        'bitcoin' => 'btc_',
        'bitcoingold' => 'bgt_',
        'dogecoin' => 'doge_',
        'bitcoinknots' => 'btc_',
        'litecoin' => 'ltc_'
    ];

    private $prefix;
    private $db;

    /**
     * Constructor
     * @param string $coin Name of the coin (bitcoin, bitcoingold, dogecoin, bitcoinknots, litecoin)
     * @param string $username RPC username
     * @param string $password RPC password
     * @param string $host RPC host (default: localhost)
     * @param int $port RPC port (optional, uses default for coin if not specified)
     * @param string $url RPC URL (optional)
     * @param string $dbHost Database host (default: localhost)
     * @param int $dbPort Database port (default: 3306)
     * @param string $dbUser Database username
     * @param string $dbPass Database password
     * @param string $dbName Database name (default: scam_database)
     */
    public function __construct($coin, $username, $password, $host = 'localhost', $port = null, $url = null, $dbHost = 'localhost', $dbPort = 3306, $dbUser, $dbPass, $dbName = 'scam_database')
    {
        $this->username = $username;
        $this->password = $password;
        $this->host = $host;
        $this->port = $port ?? $this->coinPorts[strtolower($coin)] ?? 8332;
        $this->url = $url;
        $this->CACertificate = null;

        $coin = strtolower($coin);
        $this->prefix = $this->coinPrefixes[$coin] ?? 'btc_';

        try {
            $this->db = new PDO("mysql:host={$dbHost};port={$dbPort};dbname={$dbName}", $dbUser, $dbPass);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            $this->db = null;
        }
    }

    /**
     * Get WAL ID for a wallet address if it exists in the scam database
     * @param string $address Wallet address
     * @return int|null WAL ID or null if not found or DB not available
     */
    private function getWalletId($address)
    {
        if (!$this->db) {
            return null;
        }

        try {
            $table = $this->prefix . 'wallet';
            $stmt = $this->db->prepare("SELECT WAL FROM `$table` WHERE wal_wallet = :addr");
            $stmt->execute(['addr' => $address]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return $row ? (int)$row['WAL'] : null;
        } catch (Exception $e) {
            return null;
        }
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
            'id' => $this->id++
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
            return ['error' => $curl_error];
        }

        $this->response = json_decode($this->raw_response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->error = 'JSON decode error: ' . json_last_error_msg();
            return ['error' => $this->error];
        }

        if (isset($this->response['error']) && $this->response['error'] !== null) {
            $this->error = $this->response['error'];
            return ['error' => $this->response['error']];
        }

        return $this->response['result'];
    }

    /**
     * Get transaction details with wallet analysis
     * @param string $txid Transaction ID
     * @return array JSON response with transaction details and wallet addresses with scam WAL IDs
     */
    public function getTransactionWallets($txid)
    {
        $txDetails = $this->getTransaction($txid);
        if (isset($txDetails['error'])) {
            return $txDetails;
        }

        $inputAddresses = [];
        $outputAddresses = [];
        $scamWalIds = [];

        // Extract input addresses from vin
        foreach ($txDetails['vin'] as $vin) {
            if (isset($vin['txid']) && isset($vin['vout'])) {
                $prevTx = $this->getTransaction($vin['txid']);
                if (!isset($prevTx['error']) && isset($prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses'])) {
                    $addresses = $prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses'];
                    foreach ($addresses as $addr) {
                        $inputAddresses[] = $addr;
                        $walId = $this->getWalletId($addr);
                        if ($walId !== null) {
                            $scamWalIds[$addr] = $walId;
                        }
                    }
                }
            }
        }

        // Extract output addresses from vout
        foreach ($txDetails['vout'] as $vout) {
            if (isset($vout['scriptPubKey']['addresses'])) {
                foreach ($vout['scriptPubKey']['addresses'] as $addr) {
                    $outputAddresses[] = $addr;
                    $walId = $this->getWalletId($addr);
                    if ($walId !== null) {
                        $scamWalIds[$addr] = $walId;
                    }
                }
            }
        }

        $inputAddresses = array_unique($inputAddresses);
        $outputAddresses = array_unique($outputAddresses);

        return [
            'txid' => $txid,
            'inputAddresses' => $inputAddresses,
            'outputAddresses' => $outputAddresses,
            'scamWalIds' => $scamWalIds,
            'details' => $txDetails
        ];
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
     * Get peer information to monitor connections
     * @return array JSON response with peer information
     */
    public function getPeerInfo()
    {
        return $this->request('getpeerinfo');
    }

    /**
     * Get transaction details by txid
     * @param string $txid Transaction ID
     * @return array JSON response with transaction details
     */
    private $txCache = [];
    public function getTransaction($txid)
    {
        if (isset($this->txCache[$txid])) {
            return $this->txCache[$txid];
        }
        $result = $this->request('getrawtransaction', [$txid, true]);
        if (!isset($result['error'])) {
            $this->txCache[$txid] = $result;
        }
        return $result;
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

    public function getAddressTxIds($address) {
        return $this->request('getaddresstxids', [['addresses' => [$address]]]);
    }

    /**
     * Get all transactions with details from a specific block
     * @param string|int $blockIdentifier Block hash or block height
     * @return array JSON response with detailed transactions
     */
    public function getAllBlockTransactions($blockIdentifier)
    {
        // If blockIdentifier is numeric, assume it's a block height and get block hash
        if (is_numeric($blockIdentifier)) {
            $blockHash = $this->request('getblockhash', [(int)$blockIdentifier]);
            if (isset($blockHash['error'])) {
                return $blockHash;
            }
        } else {
            $blockHash = $blockIdentifier;
        }

        // Get block details
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
     * @param int|null $startTimestamp Start timestamp for filtering (optional)
     * @param int|null $endTimestamp End timestamp for filtering (optional)
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

            // Calculate received amount (sum of outputs)
            $txReceived = 0.0;
            foreach ($txDetails['vout'] as $vout) {
                if (isset($vout['value'])) {
                    $txReceived += $vout['value'];
                }
            }
            $totalReceived += $txReceived;

            // Calculate sent amount (sum of inputs, excluding coinbase)
            $txSent = 0.0;
            if ($index > 0) { // Skip coinbase transaction
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

        // Get balance and UTXOs
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

        // Add scam WAL IDs for addresses
        $scamWalIds = [];
        foreach ($addresses as $address) {
            $walId = $this->getWalletId($address);
            if ($walId !== null) {
                $scamWalIds[$address] = $walId;
            }
        }
        if (!empty($scamWalIds)) {
            $result['scamWalIds'] = $scamWalIds;
        }

        // Get transactions if requested
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
     * Get blockchain info
     * @return array JSON response with blockchain info
     */
    public function getBlockchainInfo()
    {
        return $this->request('getblockchaininfo');
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

    /**
     * Check for received and sent payments for a wallet's addresses
     * @param array $addresses List of wallet addresses
     * @param string|null $blockHash Optional block hash to start from
     * @param int $minConfirmations Minimum number of confirmations (default: 1)
     * @return array JSON response with received and sent payments details
     */
    public function checkWalletPayments($addresses, $blockHash = null, $minConfirmations = 1, $movement = "receive")
    {
        if (!is_array($addresses) || empty($addresses)) {
            return ['error' => 'Invalid or empty address list'];
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

            if ($tx['category'] === 'receive' && ($movement === "receive" || $movement === "all")) {
                // Get sender addresses from inputs
                $senderAddresses = [];
                foreach ($txDetails['vin'] as $vin) {
                    if (isset($vin['txid']) && isset($vin['vout'])) {
                        $prevTx = $this->getTransaction($vin['txid']);
                        if (!isset($prevTx['error']) && isset($prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses'])) {
                            $senderAddresses = array_merge($senderAddresses, $prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses']);
                        }
                    }
                }

                $senderAddresses = array_unique($senderAddresses);

                // Get scam WAL IDs for senders
                $senderScamIds = [];
                foreach ($senderAddresses as $saddr) {
                    $walId = $this->getWalletId($saddr);
                    if ($walId !== null) {
                        $senderScamIds[$saddr] = $walId;
                    }
                }

                $addressScamId = $this->getWalletId($tx['address']);

                $receivedPayments[] = [
                    'txid' => $tx['txid'],
                    'address' => $tx['address'],
                    'amount' => $tx['amount'],
                    'senderAddresses' => $senderAddresses,
                    'addressScamId' => $addressScamId,
                    'senderScamIds' => $senderScamIds,
                    'blockHeight' => $txDetails['blockheight'] ?? null,
                    'confirmations' => $tx['confirmations'],
                    'time' => $tx['time'],
                    'details' => $txDetails
                ];
            } elseif ($tx['category'] === 'send' && ($movement === "send" || $movement === "all")) {
                // Get recipient addresses from outputs
                $recipientAddresses = [];
                foreach ($txDetails['vout'] as $vout) {
                    if (isset($vout['scriptPubKey']['addresses'])) {
                        $recipientAddresses = array_merge($recipientAddresses, $vout['scriptPubKey']['addresses']);
                    }
                }

                $recipientAddresses = array_unique($recipientAddresses);

                // Get scam WAL IDs for recipients
                $recipientScamIds = [];
                foreach ($recipientAddresses as $raddr) {
                    $walId = $this->getWalletId($raddr);
                    if ($walId !== null) {
                        $recipientScamIds[$raddr] = $walId;
                    }
                }

                $addressScamId = $this->getWalletId($tx['address']);

                $sentPayments[] = [
                    'txid' => $tx['txid'],
                    'address' => $tx['address'], // Address from which funds were sent
                    'amount' => abs($tx['amount']), // Use absolute value for sent amount
                    'recipientAddresses' => $recipientAddresses,
                    'addressScamId' => $addressScamId,
                    'recipientScamIds' => $recipientScamIds,
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
     * Check for received and sent payments for a wallet's addresses
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
        if ($indexStatus['addressIndexEnabled']) {
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

                    // Check for received payments
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
                        $senderAddresses = array_unique($senderAddresses);

                        // Get scam WAL IDs for senders
                        $senderScamIds = [];
                        foreach ($senderAddresses as $saddr) {
                            $walId = $this->getWalletId($saddr);
                            if ($walId !== null) {
                                $senderScamIds[$saddr] = $walId;
                            }
                        }

                        $addressScamId = $this->getWalletId($address);

                        $receivedPayments[] = [
                            'txid' => $txid,
                            'address' => $address,
                            'amount' => $receivedAmount,
                            'senderAddresses' => $senderAddresses,
                            'addressScamId' => $addressScamId,
                            'senderScamIds' => $senderScamIds,
                            'blockHeight' => $txDetails['blockheight'] ?? null,
                            'confirmations' => $confirmations,
                            'time' => $txDetails['time'] ?? null,
                            'details' => $txDetails
                        ];
                    }

                    // Check for sent payments
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
                    $recipientAddresses = array_unique($recipientAddresses);

                    if ($sentAmount > 0) {
                        // Get scam WAL IDs for recipients
                        $recipientScamIds = [];
                        foreach ($recipientAddresses as $raddr) {
                            $walId = $this->getWalletId($raddr);
                            if ($walId !== null) {
                                $recipientScamIds[$raddr] = $walId;
                            }
                        }

                        $addressScamId = $this->getWalletId($address);

                        $sentPayments[] = [
                            'txid' => $txid,
                            'address' => $address,
                            'amount' => $sentAmount,
                            'recipientAddresses' => $recipientAddresses,
                            'addressScamId' => $addressScamId,
                            'recipientScamIds' => $recipientScamIds,
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

        // Fallback to listsinceblock
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

            if ($tx['category'] === 'receive') {
                // Get sender addresses from inputs
                $senderAddresses = [];
                foreach ($txDetails['vin'] as $vin) {
                    if (isset($vin['txid']) && isset($vin['vout'])) {
                        $prevTx = $this->getTransaction($vin['txid']);
                        if (!isset($prevTx['error']) && isset($prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses'])) {
                            $senderAddresses = array_merge($senderAddresses, $prevTx['vout'][$vin['vout']]['scriptPubKey']['addresses']);
                        }
                    }
                }

                $senderAddresses = array_unique($senderAddresses);

                // Get scam WAL IDs for senders
                $senderScamIds = [];
                foreach ($senderAddresses as $saddr) {
                    $walId = $this->getWalletId($saddr);
                    if ($walId !== null) {
                        $senderScamIds[$saddr] = $walId;
                    }
                }

                $addressScamId = $this->getWalletId($tx['address']);

                $receivedPayments[] = [
                    'txid' => $tx['txid'],
                    'address' => $tx['address'],
                    'amount' => $tx['amount'],
                    'senderAddresses' => $senderAddresses,
                    'addressScamId' => $addressScamId,
                    'senderScamIds' => $senderScamIds,
                    'blockHeight' => $txDetails['blockheight'] ?? null,
                    'confirmations' => $tx['confirmations'],
                    'time' => $tx['time'],
                    'details' => $txDetails
                ];
            } elseif ($tx['category'] === 'send') {
                // Get recipient addresses from outputs
                $recipientAddresses = [];
                foreach ($txDetails['vout'] as $vout) {
                    if (isset($vout['scriptPubKey']['addresses'])) {
                        $recipientAddresses = array_merge($recipientAddresses, $vout['scriptPubKey']['addresses']);
                    }
                }

                $recipientAddresses = array_unique($recipientAddresses);

                // Get scam WAL IDs for recipients
                $recipientScamIds = [];
                foreach ($recipientAddresses as $raddr) {
                    $walId = $this->getWalletId($raddr);
                    if ($walId !== null) {
                        $recipientScamIds[$raddr] = $walId;
                    }
                }

                $addressScamId = $this->getWalletId($tx['address']);

                $sentPayments[] = [
                    'txid' => $tx['txid'],
                    'address' => $tx['address'],
                    'amount' => abs($tx['amount']),
                    'recipientAddresses' => $recipientAddresses,
                    'addressScamId' => $addressScamId,
                    'recipientScamIds' => $recipientScamIds,
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

        // Get current wallet balance and UTXOs
        $walletInfo = $this->getWalletInfo($addresses);
        if (isset($walletInfo['error'])) {
            return $walletInfo;
        }

        // Get blockchain info
        $blockchainInfo = $this->getBlockchainInfo();
        if (isset($blockchainInfo['error'])) {
            return $blockchainInfo;
        }
        $currentHeight = $blockchainInfo['blocks'];

        // Check if addressindex is enabled
        $indexStatus = $this->isAddressIndexEnabled();
        $useAddressIndex = $indexStatus['addressIndexEnabled'];

        // Get transactions (received and sent)
        $payments = $useAddressIndex
            ? $this->checkWalletPaymentsById($addresses, $blockHash, $minConfirmations)
            : $this->checkWalletPayments($addresses, $blockHash, $minConfirmations, $movement);
        if (isset($payments['error'])) {
            return $payments;
        }

        // Filter transactions by block height, timestamp, and movement
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

        // Sort transactions by time
        usort($filteredPayments, function ($a, $b) {
            $timeA = $a['time'] ?? PHP_INT_MAX;
            $timeB = $b['time'] ?? PHP_INT_MAX;
            return $timeA <=> $timeB;
        });

        // Limit number of transactions if specified
        if ($maxTransactions !== null) {
            $filteredPayments = array_slice($filteredPayments, 0, $maxTransactions);
        }

        // Calculate historical balance changes
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
                'addressesInvolved' => isset($tx['senderAddresses']) ? $tx['senderAddresses'] : $tx['recipientAddresses'],
                'scamIds' => isset($tx['senderScamIds']) ? $tx['senderScamIds'] : ($tx['recipientScamIds'] ?? [])
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
     * Check if address index is enabled
     * @return array With 'addressIndexEnabled' => bool
     */
    public function isAddressIndexEnabled()
    {
        $info = $this->getBlockchainInfo();
        // Assume it's enabled if 'getaddresstxids' is available, but for simplicity, check if command exists or assume based on coin
        // For now, return true if no error, but actually test
        $test = $this->request('getaddresstxids', [['addresses' => ['test']]]);
        return ['addressIndexEnabled' => !isset($test['error']) || strpos($test['error']['message'], 'Index not enabled') === false];
    }
}