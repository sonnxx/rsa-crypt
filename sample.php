<?php 

/**
 * 
 * Create by
 * @author  Xuân Sơn <sonnx@applancer.net>
 * @version 1.0
 * 
 */

error_reporting(-1);
ini_set('display_errors', 1);

define('ROOT_PATH', __DIR__);
define('DS', '/');

include_once ROOT_PATH . DS . 'Utils/RsaUtils.php';

$publicKey 		= 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxWVQxtFGKkvNjcZVHNcc
CYCJO95KsQ/om6PEvuQBM7lAbNXSZ5w4dwRHGjs2KgbbnpyKAtmJPHH6KmdmbwID
DUdvi68GmciMejxX7msfPFD7+ZJKpvnNESNlOqxqZf8ImglauJhooC4dFb8LzT4e
ud1RXr8fx6DRsB6pIw1Grg9XFqJSDbEcAL3+ugKBn8kQFvv58MFVkzvw1RyzKEOq
VUJyU4X5n5NQKKgujIj/ioUO3AQvagRx9BOlMqNAxfWQWEzzVIsdUJ4KZ53/L3l4
/DwJmdo6rV9OrXf2ZZb5vWM1noF4+ToIEQcCjLXmWsbbJLTGCp9EXZyreJmFyDSs
cHpkCdDLL1hZzxObPAqRSSTKYzOGgZPjcJ/X+vsMoA/Hq03w+sqd94z8EH2Qg9xw
RHHdQfl9cPfPyu4qg7ONodbvj5/O4eKHeO8soXgGVFbrNF+Xd/ynCkuedzBIdr65
8MwjIQCx6kshz2g5dAf81Zfy6cL4f1QmXm9hNVFUva3ZAfj/qGTl6rE5fQYi13aC
8tzHjwZSh5+WXgqbrhCxH/5pWVvoQPITLZtu8RE5pSeRTFXRu48vAbvZAnc5LNIN
kqzboQ4Dt0sjwDMUYZCHsbN2MaImXWrjsLXdfRaGP+mL3QriLaZAP/sDunJ0Pyv/
ezqj27sTxYFo0wSjbl++SScCAwEAAQ==';
$checksumKey 	= '5VBCZ7qI63zBSVn2pLcKzXtItyr6zipuQ+z2qSfqaQM3U7hEJwoYeg=';


$rsa_utils 		= new RsaUtils;

/**
 * gen file rsa pub&priv Key
 */
// $rsa_utils->genRSAKey(); die;

$content = json_encode([
	'title' 		=> 'Create something that must be read.',
	'description' 	=> 'Tthe National Agency for the Fight Against Illiteracy in France earned accolades for its print ad campaign. Viewers had to read the ads to discover what they were really about – not only creating awareness of the fight but also demonstrating the actual value of literacy.',
	'body' 			=> 'Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of "de Finibus Bonorum et Malorum" (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, "Lorem ipsum dolor sit amet..", comes from a line in section 1.10.32.',
	'created_time' 	=> date('Y-m-d H:i:s', time())
]);

/**
 * [$data Mã hóa dữ liệu bằng thuật toán RSA + PublicKey]
 * @var [string]
 */
$data 		= $rsa_utils->encryptData($content, $publicKey);

/**
 * [$checksum băm sha1 dữ liệu đã mã hóa nối với checksumKey và băm lại dạng md5 ]
 * @var [string]
 */
$checksum 	= md5(sha1($data) . $checksumKey);


$params['data'] 	= $data;
$params['checksum'] = $checksum;
if ($rsa_utils->checkSumData($params, $checksumKey) === true) {
	/**
	 * if === true - Kiểm tra đối soát dữ liệu không bị thay đổi 
	 * if === false - Đối soát dữ liệu bị thay đổi hoặc thuật toán băm chưa đúng
	 */
	
	/**
	 * Dịch ngược dữ liệu với publicKey
	 */
	// $params['data'] 	= $rsa_utils->decryptData($params['data'], $publicKey);

}

var_dump($params);
