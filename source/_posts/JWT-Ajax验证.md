---
title: JWT+Ajax验证
tags:
  - JavaWeb
abbrlink: 6f7d03df
date: 2020-06-30 00:28:33
typora-root-url: ..
index_img: https://rmt.dogedoge.com/fetch/~/source/unsplash/photo-1594000902228-af94a7af8e86
---

对Security和JWT的流程有了一定认识之后写的一个Demo

<!-- more -->

# 前言

​	昨天对整个Spring Security 的鉴权和授权流程有了个大概的了解，作为一个对什么都想自定义的人，肯定要去尝试一波自定义自己的权限管理。

具体代码可以看：[Gitee](https://gitee.com/gukkibokou/spring_sql) [Github](https://github.com/hukkall/security_jwt_json)

# 技术栈

- Spring Boot
- Spring Security
- Json Web Token
- MyBatis-Plus

# 系统流程

## 授权

<img src="/img/image-20200701162121415.png" alt="image-20200701162121415" style="zoom:80%;" />

## 鉴权

<img src="/img/image-20200701165911025.png" alt="image-20200701165911025" style="zoom:80%;" />

# 操作流程

## 建表

```mysql
/*
 Navicat Premium Data Transfer

 Source Server         : LOCA
 Source Server Type    : MySQL
 Source Server Version : 80019
 Source Host           : localhost:3306
 Source Schema         : boot_test

 Target Server Type    : MySQL
 Target Server Version : 80019
 File Encoding         : 65001

 Date: 01/07/2020 17:00:45
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for permission_role
-- ----------------------------
DROP TABLE IF EXISTS `permission_role`;
CREATE TABLE `permission_role`  (
  `PREMISSION_ID` int(0) NOT NULL,
  `ROLE_ID` int(0) NOT NULL,
  INDEX `PREMISSION_ID`(`PREMISSION_ID`) USING BTREE,
  INDEX `ROLE_ID1`(`ROLE_ID`) USING BTREE,
  CONSTRAINT `PREMISSION_ID` FOREIGN KEY (`PREMISSION_ID`) REFERENCES `premission` (`ID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT `ROLE_ID1` FOREIGN KEY (`ROLE_ID`) REFERENCES `role` (`ROLE_ID`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of permission_role
-- ----------------------------
INSERT INTO `permission_role` VALUES (1, 1);
INSERT INTO `permission_role` VALUES (2, 2);

-- ----------------------------
-- Table structure for premission
-- ----------------------------
DROP TABLE IF EXISTS `premission`;
CREATE TABLE `premission`  (
  `ID` int(0) NOT NULL,
  `PERMISSION` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  PRIMARY KEY (`ID`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of premission
-- ----------------------------
INSERT INTO `premission` VALUES (1, 'check:edit:delete');
INSERT INTO `premission` VALUES (2, 'view');

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role`  (
  `ROLE_ID` int(0) NOT NULL,
  `ROLE_NAME` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  PRIMARY KEY (`ROLE_ID`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES (1, 'admin');
INSERT INTO `role` VALUES (2, 'user');

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `ID` bigint(0) NOT NULL AUTO_INCREMENT,
  `NAME` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `PASSWORD` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  PRIMARY KEY (`ID`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES (1, 'admin', '$2a$10$4tCuODS2p98tvk8EWtlhd.Mdbk1mXPwbruD4Y2VL.STIaP2Avz5bi');
INSERT INTO `user` VALUES (2, 'user', '$2a$10$UiSHiNwZdZ2mUSOf7bNCfONRNhMdwAJ37dJ9YVTjPvTfPPKWoLiuy');

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role`  (
  `USER_ID` bigint(0) NOT NULL,
  `ROLE_ID` int(0) NOT NULL,
  `ID` int(0) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`ID`) USING BTREE,
  INDEX `USER_ID`(`USER_ID`) USING BTREE,
  INDEX `ROLE_ID`(`ROLE_ID`) USING BTREE,
  CONSTRAINT `ROLE_ID` FOREIGN KEY (`ROLE_ID`) REFERENCES `role` (`ROLE_ID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT `USER_ID` FOREIGN KEY (`USER_ID`) REFERENCES `user` (`ID`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user_role
-- ----------------------------
INSERT INTO `user_role` VALUES (1, 1, 1);
INSERT INTO `user_role` VALUES (2, 2, 2);

SET FOREIGN_KEY_CHECKS = 1;

```

## 代码生成

​	这里我使用了Mybatis-Plus的代码生成器

```java
//1、全局配置
        GlobalConfig config = new GlobalConfig();
        String projectPath = System.getProperty("user.dir");
        config.setActiveRecord(true)//开启AR模式
                .setAuthor("")//设置作者
                .setOutputDir(projectPath + "/src/main/java")//生成路径(一般在此项目的src/main/java下)
                .setFileOverride(true)//第二次生成会把第一次生成的覆盖掉
                //.setSwagger2(true)//实体属性 Swagger2 注解
                .setIdType(IdType.AUTO)//主键策略
                .setServiceName("%sService")//生成的service接口名字首字母是否为I，这样设置就没有I
                .setBaseResultMap(true)//生成resultMap
                .setBaseColumnList(true);//在xml中生成基础列
        //2、数据源配置
        DataSourceConfig dataSourceConfig = new DataSourceConfig();
        dataSourceConfig.setDbType(DbType.MYSQL)//数据库类型
                .setDriverName("com.mysql.cj.jdbc.Driver")
                .setUrl("jdbc:mysql://localhost:3306/xiaoluo?useSSL=true&serverTimezone=GMT")
                .setUsername("root")
                .setPassword("你的密码");
        //3、策略配置
        StrategyConfig strategyConfig = new StrategyConfig();
        strategyConfig.setCapitalMode(true)//开启全局大写命名
                .setNaming(NamingStrategy.no_change)//表名映射到实体的命名策略(下划线到驼峰)
                //表字段映射属性名策略(未指定按naming)
                .setColumnNaming(NamingStrategy.no_change)
                //.setTablePrefix("tb_")//表名前缀
                //.setSuperEntityClass("你自己的父类实体,没有就不用设置!")
                //.setSuperEntityColumns("id");//写于父类中的公共字段
                //.setSuperControllerClass("自定义继承的Controller类全称，带包名,没有就不用设置!")
                .setRestControllerStyle(true) //生成 @RestController 控制器
                .setEntityLombokModel(true);//使用lombok
        //4、包名策略配置
        PackageConfig packageConfig = new PackageConfig();
        packageConfig.setParent("com.gukki")//设置包名的parent
                .setMapper("mapper")

                .setService("service")
                .setController("controller")
                .setEntity("entity")
                .setXml("mapper");//设置xml文件的目录
        //5、整合配置
        AutoGenerator autoGenerator = new AutoGenerator();
        autoGenerator.setGlobalConfig(config)
                .setDataSource(dataSourceConfig)
                .setStrategy(strategyConfig)
                .setPackageInfo(packageConfig);
        //6、执行
        autoGenerator.execute();
```

执行即可自动生成代码

## 编写JWT工具类 JWTUtil

```java
@Slf4j
@Component
public class JWTUtil implements Serializable {
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;
    private static String key = "imakeytolong";

    //第二个参数意思是指定用什么方法处理这段token
    //换言之就是调用什么方法去获取这段token里面的值
    //由T决定返回类型
    //指定好方法，期望将输入的token 转换为输出值
    /*
        猜测resolve.apply等价于：{claims->传入的函数体}
        即，T为函数的返回类型，Claim为传入的函数类型。
     */
    public static <T> T getClaimFromToken(String token, Function<Claims, T> resolve) {
        Claims claims = getAllClaims(token);
        return resolve.apply(claims);
    }
    //注意，这里要用valueOf方法，我在这里出过一次问题。
    public static Long getUserID(String token){
        return Long.valueOf(getClaimFromToken(token,Claims::getId));
    }
    //Get All Claims
    public static Claims getAllClaims(String token) {
        return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
    }
    //获取JWT的载荷部分
    public static String getAClaim(String token,String claimName){
        return getAllClaims(token).get(claimName).toString();
    }
    //获取主题名，也就是用户名
    public static String getUserNameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //获得token过期时间
    public static Date getExpirationDate(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    //查询token 是否过期
    private static Boolean isExpired(String token) {
        Date date = getExpirationDate(token);
        return date.before(new Date());
    }

    //生成一串token给用户
    public static String genKey(SecurityUser details) {
        return doGenkey(details);
    }

    //生成
    private static String doGenkey(SecurityUser details) {
        System.out.println(details.getId());
        return Jwts.builder()
                .setId(String.valueOf(details.getId()))
                .claim("authorities", JSON.toJSONString(details.getAuthorities()))
                .setSubject(details.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 100))
                .signWith(SignatureAlgorithm.HS256, key).compact();
    }

    //校验
    public static Boolean verifyToken(String token, UserDetails details) {
        final String name = details.getUsername();
        return (name.equals(getUserNameFromToken(token)) && !isExpired(token));
    }
}
```

## 编写返回结果类 ResUtil

```java
@Slf4j
public class ResUtil {
    //转换为JSON输出
    public static void ResponseJSON(ServletResponse resp, Map<String, Object> resultMap) {
        PrintWriter pw = null;
        try {
            resp.setCharacterEncoding("UTF-8");
            resp.setContentType("application/json");
            pw = resp.getWriter();
            pw.println(JSON.toJSONString(resultMap));
        } catch (IOException e) {
            log.error(e.getMessage());
        } finally {
            if (pw != null) {
                pw.flush();
                pw.close();
            }
        }
    }

    public static Map<String, Object> Success() {
        Map<String, Object> map = new HashMap<>();
        map.put("result", "Success");
        map.put("code", 200);
        return map;
    }

    public static Map<String, Object> Fail() {
        Map<String, Object> map = new HashMap<>();
        map.put("result", "Fail");
        map.put("code", 500);
        return map;
    }

    public static Map<String, Object> CustomResult(int code, String msg) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("result", msg);
        map.put("code", code);
        return map;
    }
}
```

## 登录流程 

### JSON认证处理类 JSONAuthFilter

​	为了替换掉自带的表单提交，我们需要重写`UsernamePasswordAuthenticationFilter`类里的`attemptAuthentication`方法。

我利用`FastJson`将提交过来的JSON转换为一个Map，从里面提取到用户名、密码等信息，组装成一个符合Security标准的认证类并请求认证。注意，此时密码和用户名都没认证，所以这个用户的权限信息是`null`。这些鉴定的事情是交给我自定义的认证类干的。

```java
@Component
@Slf4j
public class JSONAuthFilter extends UsernamePasswordAuthenticationFilter {
    @Override
    @Autowired
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    @Autowired
    LoginSuccessHandler successHandler;
    @Autowired
    LoginFailureHandler failureHandler;
    @Autowired
    AccessDenied accessDenied;
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("进入了JSON登陆许可校验");
        if (request.getContentType().equals(MediaType.APPLICATION_JSON_UTF8_VALUE) || request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)) {
            UsernamePasswordAuthenticationToken token = null;
            try(InputStream inputStream = request.getInputStream()) {
                Map<String,String> map = JSON.parseObject(inputStream, Charset.defaultCharset(),Map.class);
                token = new UsernamePasswordAuthenticationToken(map.get("username"),map.get("password"));
                //定义好这个过滤器所处理的url
                setFilterProcessesUrl("/login");
                //定义好登陆失败的处理类
                setAuthenticationFailureHandler(failureHandler);
                //定义好登录成功的处理类，这很重要，因为我这里装配JWT的地方就是这个处理类。
                setAuthenticationSuccessHandler(successHandler);
            } catch (IOException e) {
                logger.error(e.getMessage());
                token = new UsernamePasswordAuthenticationToken("","");
            }finally {
                setDetails(request,token);
                //请求认证，这就调用了我的自定义的认证类。
                return this.getAuthenticationManager().authenticate(token);
            }
        }
        else{
            return super.attemptAuthentication(request,response);
        }
    }
}
```

### 自定义的认证类 CustomAuthProvider

​	得到上面传来的用户名和密码，我们就需要从数据库里面拿到对应用户名的个人信息并进行比对了，匹配成功之后我们就可以去认证成功类装配JWT了。若想实现自定义认证，需要实现`AuthenticationProvider`这个类下的`authenticate`方法

```java
@Slf4j
@Component
public class CustomAuthProvider implements AuthenticationProvider {
    @Autowired
    CustomUserDetailService userDetailService;
    @Autowired
    UserRoleService userRoleService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("进入了登录监测");
        String name = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        SecurityUser user = userDetailService.loadUserByUsername(name);
        log.info(user.toString());
        if (user == null) {
            throw new UsernameNotFoundException("未找到用户名");
        } else if (!new BCryptPasswordEncoder().matches(password, user.getPassword())) {
            throw new BadCredentialsException("密码错误");
        }
        // 获取角色列表
        HashSet<GrantedAuthority> authorities = new HashSet<>();
        /*
        	SELECT
            role.ROLE_ID,
            role.ROLE_NAME
        FROM
            role
                LEFT JOIN
            user_role
            ON
                role.ROLE_ID = user_role.ROLE_ID
        WHERE
            user_role.USER_ID = #{id}
        */
        List<Role> list = userRoleService.getRoleByID(user.getId());
        //Lambda 表达式 将获取到的角色处理之后放入用户信息中的权限组
        list.forEach(userRole -> authorities.add(new SimpleGrantedAuthority("ROLE_" + userRole.getRoleName())));
        user.setAuthorities(authorities);
        //认证成功之后返回一个充满了用户信息的类，以及他所有的权限信息。
        return new UsernamePasswordAuthenticationToken(user, null, authorities);
    }

    //其实这里可以做一些判断，判断传入的认证类是否被这个所支持。
    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
```

### 自定义认证成功类 LoginSuccessHandler

​	这个类功能很简单，如果认证成功之后认证类会传回一个充满个人信息的认证类，我们将这个类组装成一个JWT，并且返回给用户。

若想实现这个功能，需实现`AuthenticationSuccessHandler`下的`onAuthenticationSuccess`方法

```java

@Component
@Slf4j
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        SecurityUser user = (SecurityUser) authentication.getPrincipal();
        log.info(user.toString());
        String token = JWTUtil.genKey(user);
        HashMap<String, Object> map = new HashMap<>();
        map.put("token",token);
        ResUtil.ResponseJSON(response,map);
    }
}
```

这样的话，用户就能拿到他的token了。

### 注册到Spring Security SecurityConfig

​	写完这些类还不算完，需要将其注册到Security的配置里面去。

```java
@Slf4j
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    JSONAuthFilter filter;
    ...
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ...
        http.addFilterAt(filter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

登录的流程就差不多了，可以看下结果：

![image-20200701180435010](/img/image-20200701180435010.png)

## 鉴权流程

### Token认证类 JWTAuthFilter

​	由于JWT是一种无状态的应用授权方式，即，服务器不保存用户信息，而是用户每次访问的时候都要带上JWT。所以需要一个类去获取到请求头上的Token并进行解析与认证。需要继承`BasicAuthenticationFilter`并重写`doFilterInternal`方法。

```java
@Slf4j
//认证
//流程：检查请求头有无认证信息，有->从Token中获取用户信息，获取角色组->组装成一个用户信息类（继承了UserDetails）—>封装成一个认证类->提交至安全上下文。
public class JWTAuthFilter extends BasicAuthenticationFilter {

    public JWTAuthFilter(AuthenticationManager manager) {
        super(manager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("进入了Token认证");
        String header = request.getHeader("Authorization");
        if (null != header && header.startsWith("Bearer ")) {
            String token = header.substring(7);

            //Get name
            String name = JWTUtil.getUserNameFromToken(token);
            //Get ID
            Long ID = JWTUtil.getUserID(token);
            //获取角色
            if (!name.isEmpty() && (ID != null)) {
                try {
                    List<GrantedAuthority> authorityList = new ArrayList<>();
                    String authority = JWTUtil.getAClaim(token, "authorities");
                    if (!authority.isEmpty()) {
                        //[{"authority":"ROLE_USER"},{"authority":"ROLE_ADMIN"}]
                        List<Map<String, String>> authorityMap = JSONObject.parseObject(authority, List.class);
                        for (Map<String, String> map : authorityMap) {
                            if (!map.isEmpty()) {
                                authorityList.add(new SimpleGrantedAuthority(map.get("authority")));
                            }
                        }
                        SecurityUser user = new SecurityUser(ID, name, authorityList);
                        UsernamePasswordAuthenticationToken token1 = new UsernamePasswordAuthenticationToken(user, null, authorityList);
                        //保存到安全上下文，等会鉴权时用到。
                        SecurityContextHolder.getContext().setAuthentication(token1);
                    }
                } catch (ExpiredJwtException e) {
                    logger.error(e.getMessage());
                } catch (Exception e) {
                    logger.error(e.getMessage());
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

### 注册到Spring Security

```java
@Slf4j
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    ...
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ...
        http.addFilter(new JWTAuthFilter(authenticationManager()));
    }
}
```

一般来讲，如果是以角色(`hasRole`)来判断能否访问资源的话（就像下面的一样），到这里就结束了

```java
@PreAuthorize("hasRole('admin')")
    @RequestMapping("/admin")
    public String test() {
        return "Success";
    }
```

但是有时事情并没有那么简单，比如多人合作的一份文档，有人可以编辑，有人可以删除，有人只可以查看，所以我们要把权限控制的粒度细化一些。也就是说什么人可以干什么事情之类的，但是我这里**没这样写**，~~只能等以后了~~。只写了一个什么角色对有着什么操作权限，对于一个已经限定好操作权限的资源，不管你的角色是什么，只要你有它所要求的权限就可以对他操作了。



### 自定义权限比较器 CustomEvaluator

​	需要实现`PermissionEvaluator`下的`hasPermission`方法

```java
@Slf4j
@Component
public class CustomEvaluator implements PermissionEvaluator {
    @Autowired
    PermissionRoleService service;
    //authentication 会自动传进去的。
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        SecurityUser user = (SecurityUser) authentication.getPrincipal();
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        Set<String> permissions = new HashSet<>();
        List<Permission> permissionList = service.getPremissionByID(user.getId());
        permissionList.forEach(item -> {permissions.add(item.getPermission());});
        if(permissions.contains(permission.toString())) return true;
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
```

对于：

```java
@PreAuthorize("hasPermission('/user/user','view:edit')")
    @RequestMapping("/user")
    public String user(){
        return "User Success";
    }
```

这种形式的的，只要你的权限里面有`view:edit`这两个权限，都可以访问这个链接。



-大概就结束了？