# JWT

## 自用JWT

## 超简单 超烂

## 开始

```
// 加密所用KEY 保证JWT安全性 每个项目都应该不一样 并且不要泄露
$key = 'keykeykeykeykey465414213145353453';

// 需要存入JWT中的数据 为一个数组
// 如果必须要存储一些敏感数据使用password_hash[PASSWORD_BCRYPT]加密并使用password_verify验证
$data = [
  'id' => 1,
  'data' => [
    'user' => 'name',
    'sex' => 'female'
  ]
];

// 默认配置 JWT启用时间 过期时间等
$config = [

];

// 生成JWT [$data] [$key] [$config]
$jwt = JWT::start($data, $key, $config);

// 验证JWT 返回200说明正常
JWT::check($jwt, $key);

// 获取某个变量所对应的值 生成JWT时 $data 中的数据
// 是否需要验证 为一个bool值 默认为true 如果之前手动验证了 可以使用false
// 是否需要验证为 false 时 $key 不用传
JWT::get($jwt, 'id', [是否需要验证(true/false)], $key);

// 通 get 返回整个 $data 
JWT::data($jwt, [是否需要验证(true/false)], $key);
```

```
使用函数 需要提前配置好 KEY 和 默认PAYLOAD即上面的$config
$jwt = jwt_start($data);

$data = jwt_data($jwt);
```
