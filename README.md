# JWT

## 自用JWT

## 超简单 超烂

## 开始

```
JWT::start([数据数组], [加密KEY], [默认PAYLOAD]);

JWT::check([JWT], [加密KEY]);

JWT::get([JWT], [字段名], [是否需要验证], [加密KEY]);

JWT::get([JWT], [是否需要验证], [加密KEY]);
```

```
$jwt = jwt_start([数据数组]);

$data = jwt_data($jwt);
```
