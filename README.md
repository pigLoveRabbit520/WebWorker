WebWorker
========

基于Workerman实现的自带http server的web开发框架，用于开发高性能的api应用，例如app接口服务端等。 


特性
========
* 仅只支持php7
* 天生继承workerman所拥有的特性
* 只实现了简单路由功能的小巧框架,便于开发者使用和扩展.demo1中只是目录示例，开发者可自行定义自己的应用目录结构
* slim风格添加路由
* 集成了workerman-statistics项目，可以监控服务情况
* 支持中间件

安装
========

```
composer require salamander/webworker
```

快速开始
======
demo.php
```php
<?php
use Workerman\Worker;
use Workerman\Protocols\Http;
use WebWorker\Libs\Mredis;
use WebWorker\Libs\Mdb;
use WebWorker\Libs\Mmysqli;

define('APP_ROOT', str_replace('\\', '/', dirname(__FILE__)));
require_once __DIR__.'/vendor/autoload.php';

//加载配置文件
define("WORKERMAN_RUN",getenv("WORKERMAN_RUN"));

$containerConfig = [
    'settings' => [
        'displayErrorDetails' => true, // set to false in production
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header,
        'determineRouteBeforeAppMiddleware' => true
    ]
];

$app = new WebWorker\App("http://0.0.0.0:8888", [], $containerConfig);

$app->name = "newSayu66";

$app->count = 30;

$app->max_request = 1000;

//设置监控
$app->statistic_server = "udp://127.0.0.1:55656";

$app->get('/', function ($req, $res) {
    $res->getBody()->write('hello salamander');
});

$app->get('/name', function ($req, $res) {
    $res->getBody()->write('hello name');
});

//初始化redis和mysqli连接
$app->onWorkerStart = function($worker) {

};

$app->onWorkerReload = function ($worker) {

};


// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
```