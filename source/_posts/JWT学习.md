---
title: JWT学习
tags:
  - JavaWeb开发
  - SpringSecurity
  - JWT
abbrlink: cec8f3e6
date: 2020-06-29 14:39:37
typora-root-url: ..
index_img: https://rmt.dogedoge.com/fetch/~/source/unsplash/photo-1594145235947-de84b8ec131b
---

一个新手对于JWT的认识

<!-- more -->

# JWT 学习

## 1、概念

​	 JWT(Jason Web Token)按照我个人理解，是一串服务端按照特定的加密算法生成的字符串。

​	在用户登录成功之后，服务器将用户的个人信息加密并签名成一串字符串发送回用户浏览器，在每次访问受权限控制的网页的时候将这串字符串发回给服务器，用于证明“你还是你”。然后服务端可以解密这串字符串，从里面拿到用户的相关信息，并判断用户有无权限访问此页面。

​	绿小萝的开发中，我们采用了传统的session来记录用户信息，这样在本地或者说单机开发是没有什么问题。但是一旦出现前后端分别处于不同的服务器里，产生了跨域的问题，这样的话session就比较难处理了。

​	采用JWT的话，服务器不保存用户的session，只凭JWT里面的信息来鉴别用户，这样的话，跨域就变得很简单了。

​	JWT这个字符串由三个结构组成

>- 头部(Header)
> - "alg" 加密类型
> - "typ" 这串token的类型，自然是JWT
>- 载荷(PayLoad)
> - 可自定义，采用键值对的方式
>- 签名
> - 与服务端指定的密匙有关

​	附：我们使用的session认证流程：

>1. 用户登录，发送用户名和密码到后台
>2. 后台验证通过之后，将从数据库取出来的用户信息保存到session里
>3. 后台向用户浏览器返回一个session_id，写入浏览器的cookie里。
>4. 之后的每一个请求，都会将cookie里面的session_id发送回后台
>5. 后台通过前台传来的session_id，找到保存起来的session，并从里面取得用户信息。

## 2、小试牛刀

​	网上找了个教程，讲的很好，我模仿他的例子，加上了自己理解的注释：

```java
void contextLoads() {
        String s = genToken();
        verifyToken(s);

    }
	//生成JWT
    private String genToken() {
        //先生成token，预设好一个Key
        String secret = "imkey";
        //加密
        Algorithm algorithm = Algorithm.HMAC256(secret);
        //设置头部信息
        //也就是加密算法类型以及token类型
        Map<String, Object> map = new HashMap<>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        //设置载荷（payload）
        String token = JWT.create()
                //定义头部
                .withHeader(map)
                //自定义载荷
                .withClaim("name", "李一")
                //定义主题
                .withSubject("一个token")
                //签名头部
                .sign(algorithm);
        return token;
    }
	//校验JWT
    private void verifyToken(String token){
        //定义加密类型
        Algorithm algorithm = Algorithm.HMAC256("imkey");
        //获取这种算法的对应的解密（校验）对象
        JWTVerifier require = JWT.require(algorithm)
                .build();
        System.out.println(require);
        //解密
        DecodedJWT decodedJWT = require.verify(token);
        //获取载荷里面的值
        Claim claim = decodedJWT.getClaim("name");
        System.out.println(claim);
        //输出载荷的值
        System.out.println(claim.asString());
    }
```

运行结果如下：

![image-20200626083111707](/img/image-20200626083111707-1593413542002.png)

是没有问题的。

## 3、使用ajax发送用户信息并进行登录认证的JWT应用

​		项目结构如下所示

![image-20200626122914327](/img/image-20200626122914327.png)

流程图（[引用了一个大佬的图](https://www.cnblogs.com/fishpro/p/spring-boot-study-securing-jwt.html)，详情请见本章末尾）

![o_jwt2](/img/o_jwt2.jpg)

![o_jwt3](/img/o_jwt3.jpg)

![o_jwt4](/img/o_jwt4.jpg)

**JwtAuthenticationController**

```java
/**
 * 用于验证 jwt 返回客户端 jwt（json web token）
 * */
@RestController
@CrossOrigin
public class JwtAuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    /**
     * 获取 客户端来的 username password 使用秘钥加密成 json web token
     * */
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {
        //获取前台传来的明文账号密码并进行认证
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        //认证操作成功后，以下的语句才会执行


        //获取用户信息
        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());
        //生成token
        final String token = jwtTokenUtil.generateToken(userDetails);
        //向前台返回序列化后的token
        return ResponseEntity.ok(new JwtResponse(token));
    }

    /**
     *  获取 客户端来的 username password 使用秘钥加密成 json web token
     * */
    private void authenticate(String username, String password) throws Exception {
        try {
            //创建一个没有认证的token实例，此时“是否身份认证过”属性为false
            //由于此时未进行身份认证，所以他的权限未知

            //认证信息管理（authenticationManager），从指定的用户数据源加载用户信息
            //然后使用约定好的加密方式，进行认证。
            //认证失败之后，直接返回给前台401
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
```

**JwtAuthenticationEntryPoint**

```java
/**
 * AuthenticationEntryPoint 用来解决匿名用户访问无权限资源时的异常
 * AccessDeineHandler 用来解决认证过的用户访问无权限资源时的异常
 * */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    private static final long serialVersionUID = -7858869558953243875L;

    //当出错的时候 发送 Unauthorized
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}

```

**JwtRequestFilter**

```java
/**
 * 过滤器 用于 Spring Boot Security
 * OncePerRequestFilter 一次请求只通过一次filter，而不需要重复执行
 * */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        //获得请求头
        final String requestTokenHeader = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;
        // JWT Token 获取请求头部的 Bearer
        // only the Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                //从token里获取用户名
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                System.out.println("JWT Token has expired");
            }
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        // 验证
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //我猜，之所以要在这里再校验一次用户名，是防止上面的异常抛出的后，username为空的情况。
            //获取用户的在后台保存的账号密码，封装成一个对象，通过查询用户名的方式
            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);

            // JWT 验证通过 使用Spring Security 管理
            //将token里面的用户名和保存的对象进行校验
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                //传入用户信息，
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the
                // Spring Security Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        //没有token，则跑去jwtcontroller
        chain.doFilter(request, response);
    }

}
```

**JwtUserDetailsService**

```java
//用户信息来源
@Service
public class JwtUserDetailsService implements UserDetailsService {
//通过用户名加载
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("javainuse".equals(username)) {
            //新建一个用户名为：javainuse的用户，密码为用BC加密的password,后面的数组是这个用户的权限列表，目前为空。
            //BC加密后的字符串有着它特殊的意思，前面的2a表示使用了bc加密，后面的10表示它hash了10次
            //然后从第三个$开始算起的21个字符都是它的salt，用于混淆用的
            //后面的全都是密文密码和slat hash10次之后的密文
            //如何校验？
            //获得前台传来的明文密码，取储存好的BC加密后的字符串，取其中的盐，hash10次之后，和密文进行匹配。


            //返回用户的用户名、BC加密后的密码、以及权限列表。
            return new User("javainuse", "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6",
                    new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }
}

```

**WebSecurityConfig**

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    private UserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        // configure AuthenticationManager so that it knows from where to load
        // user for matching credentials
        // Use BCryptPasswordEncoder
        //配置用于用户信息来源，并设置好加密方式
        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        // 本示例不需要使用CSRF
        httpSecurity.csrf().disable()
                // 认证页面不需要权限
                .authorizeRequests().antMatchers("/authenticate").permitAll().
                //其他页面
                        anyRequest().authenticated().and().
                //登录页面 模拟客户端
                formLogin().loginPage("/login.html").permitAll().and().
                // store user's state.
                 exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).and().sessionManagement()
                //不使用session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //验证请求是否正确
        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

**HelloWorldController**

```java
@RestController
public class HelloWorldController {

    @RequestMapping({ "/hello" })
    public String firstPage() {
        return "Hello World";
    }

}
```

**JwtRequest**

```java
public class JwtRequest{

   // private static final long serialVersionUID = 5926468583005150707L;

    private String username;
    private String password;

    //need default constructor for JSON Parsing
    public JwtRequest()
    {

    }

    public JwtRequest(String username, String password) {
        this.setUsername(username);
        this.setPassword(password);
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

**JwtResponse**

```java
public class JwtResponse implements Serializable {

    private static final long serialVersionUID = -8091879091924046844L;
    private final String jwttoken;

    public JwtResponse(String jwttoken) {
        this.jwttoken = jwttoken;
    }

    public String getToken() {
        return this.jwttoken;
    }
}
```

**JwtTokenUtil**

```java
@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -2550185165626007488L;

    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    @Value("${jwt.secret}")
    private String secret;

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    //校验 token
    public Boolean validateToken(String token, UserDetails userDetails) {
        //获取token的用户名，并进行匹配
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}

```

登录用的ajax：

```javascript
$(function() {
        $("#btnSave").click(function () {
            var username=$("#userName").val();
            var password=$("#password").val();
            $.ajax({
                cache: true,
                type: "POST",
                url: "/authenticate",
                contentType: "application/json;charset=UTF-8",
                data:JSON.stringify({"username":username ,"password" : password}),
                dataType: "json",
                async: false,
                error: function (request) {
                    console.log("Connection error");
                },
                success: function (data) {
                    //save token
                    localStorage.setItem("token",data.token);


                }
            });
        });
    });
```

注意，这个项目的java版本要求是java8，如果你是和我一样使用java11或更高的版本的话，可以使用我的pom.xml里面的配置。

```xml
<dependencies>
        <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-impl</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-core</artifactId>
            <version>2.3.0</version>
        </dependency>
        <dependency>
            <groupId>javax.activation</groupId>
            <artifactId>activation</artifactId>
            <version>1.1.1</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
```

参考来源：

[Spring Boot Security JWT 整合实现前后端分离认证示例](https://www.cnblogs.com/fishpro/p/spring-boot-study-securing-jwt.html)

[Spring Boot Security + JWT Hello World Example](https://www.javainuse.com/spring/boot-jwt)



## 4、 JWT+数据库 授权部分

​	我觉得这玩意可难了，学了个两天才勉勉强强搞明白个一小半。唉，吃了英语不好的亏。

​	以下是大概的流程：

<img src="/img/image-20200628170759526.png" alt="A" style="zoom: 100%;" />

所用到的类：

### 拦截器类 JWTAuthenticationTokenFilter

```java
public class JWTAuthenticationTokenFilter extends BasicAuthenticationFilter {

    public JWTAuthenticationTokenFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 获取请求头中JWT的Token
        String tokenHeader = request.getHeader(JWTConfig.tokenHeader);
        // && tokenHeader.startsWith(JWTConfig.tokenPrefix)
        if (null!=tokenHeader) {
            try {
                // 截取JWT前缀
                String token = tokenHeader.replace("Bearer Sans-", "");
                // 解析JWT
                Claims claims = Jwts.parser()
                        .setSigningKey(JWTConfig.secret)
                        .parseClaimsJws(token)
                        .getBody();
                log.info(claims.toString());
                // 获取用户名
                String username = claims.getSubject();
                String userId=claims.getId();
                if(!StringUtils.isEmpty(username)&&!StringUtils.isEmpty(userId)) {
                    // 获取角色
                    List<GrantedAuthority> authorities = new ArrayList<>();
                    String authority = claims.get("authorities").toString();
                    log.info(authority);
                    if(!StringUtils.isEmpty(authority)){
                        List<Map<String,String>> authorityMap = JSONObject.parseObject(authority, List.class);
                        for (Map<String, String> stringStringMap : authorityMap) {
                            for (String s : stringStringMap.keySet()) {
                                log.info(s);
                                log.info(stringStringMap.get(s));
                            }
                        }
                        for(Map<String,String> role : authorityMap){
                            if(!StringUtils.isEmpty(role)) {
                                authorities.add(new SimpleGrantedAuthority(role.get("authority")));
                                //log.info(role.get("authority"));
                            }
                        }
                    }
                    //组装参数
                    SelfUserEntity selfUserEntity = new SelfUserEntity();
                    selfUserEntity.setUsername(claims.getSubject());
                    selfUserEntity.setUserId(Long.parseLong(claims.getId()));
                    selfUserEntity.setAuthorities(authorities);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(selfUserEntity, userId, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (ExpiredJwtException e){
                log.info("Token过期");
            } catch (Exception e) {
                log.error(e.getMessage());
                log.info("Token无效");
            }
        }
        filterChain.doFilter(request, response);
        return;
    }
}
```

### Security配置类 SecurityConfig

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //开启权限注解,默认是关闭的
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 自定义登录成功处理器
     */
    @Autowired
    private UserLoginSuccessHandler userLoginSuccessHandler;
    /**
     * 自定义登录失败处理器
     */
    @Autowired
    private UserLoginFailureHandler userLoginFailureHandler;
    /**
     * 自定义注销成功处理器
     */
    @Autowired
    private UserLogoutSuccessHandler userLogoutSuccessHandler;
    /**
     * 自定义暂无权限处理器
     */
    @Autowired
    private UserAuthAccessDeniedHandler userAuthAccessDeniedHandler;
    /**
     * 自定义未登录的处理器
     */
    @Autowired
    private UserAuthenticationEntryPointHandler userAuthenticationEntryPointHandler;
    /**
     * 自定义登录逻辑验证器
     */
    @Autowired
    private UserAuthenticationProvider userAuthenticationProvider;

    /**
     * 加密方式
     * @Author Sans
     * @CreateTime 2019/10/1 14:00
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
    /**
     * 注入自定义PermissionEvaluator
     */
    @Bean
    public DefaultWebSecurityExpressionHandler userSecurityExpressionHandler(){
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setPermissionEvaluator(new UserPermissionEvaluator());
        return handler;
    }

    /**
     * 配置登录验证逻辑
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth){
        //这里可启用我们自己的登陆验证逻辑
        auth.authenticationProvider(userAuthenticationProvider);
    }
    /**
     * 配置security的控制逻辑
     * @Author Sans
     * @CreateTime 2019/10/1 16:56
     * @Param  http 请求
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 不进行权限验证的请求或资源(从配置文件中读取)
               .antMatchers(JWTConfig.antMatchers.split(",")).permitAll()
                // 其他的需要登陆后才能访问
                .anyRequest().authenticated()
                .and()
                // 配置未登录自定义处理类
                .httpBasic().authenticationEntryPoint(userAuthenticationEntryPointHandler)
                .and()
                // 配置登录地址
                .formLogin()
                .loginProcessingUrl("/login/userLogin")
                // 配置登录成功自定义处理类
                .successHandler(userLoginSuccessHandler)
                // 配置登录失败自定义处理类
                .failureHandler(userLoginFailureHandler)
                .and()
                // 配置登出地址
                .logout()
                .logoutUrl("/login/userLogout")
                // 配置用户登出自定义处理类
                .logoutSuccessHandler(userLogoutSuccessHandler)
                .and()
                // 配置没有权限自定义处理类
                .exceptionHandling().accessDeniedHandler(userAuthAccessDeniedHandler)
                .and()
                // 开启跨域
                .cors()
                .and()
                // 取消跨站请求伪造防护
                .csrf().disable();

        // 基于Token不需要session
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // 禁用缓存
        http.headers().cacheControl();
        // 添加JWT过滤器
        http.addFilter(new JWTAuthenticationTokenFilter(authenticationManager()));
    }
}
```



### 角色实体类 SysRoleEntity

```java
@Data
@TableName("sys_role")
public class SysRoleEntity implements Serializable {
	private static final long serialVersionUID = 1L;
	/**
	 * 角色ID
	 */
	@TableId
	private Long roleId;
	/**
	 * 角色名称
	 */
	private String roleName;
}
```



###  自定义认证逻辑处理器 UserAuthenticationProvider

```java
public class UserAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private SelfUserDetailsService selfUserDetailsService;
    @Autowired
    private SysUserService sysUserService;
    //authentication 这个参数是哪里来的呢？
    //我猜测是这样的：UsernamePasswordAuthenticationFilter 处理了从前台传入的账号密码，封装成一个实现了Authentication接口的UsernamePasswordAuthenticationToken类，此时这个账号密码尚未认证，所以没有权限。->调用ProviderManager类的authenticate方法处理Token->轮询在security配置里面注册好的登录逻辑处理类，检查是否支持当前token，找到之后进行处理。—>于是，这个token就传进来了。
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取表单输入中返回的用户名
        String userName = (String) authentication.getPrincipal();
        // 获取表单中输入的密码
        String password = (String) authentication.getCredentials();
        // 查询用户是否存在
        SelfUserEntity userInfo = selfUserDetailsService.loadUserByUsername(userName);
        if (userInfo == null) {
            throw new UsernameNotFoundException("用户名不存在");
        }
        // 我们还要判断密码是否正确，这里我们的密码使用BCryptPasswordEncoder进行加密的
        if (!new BCryptPasswordEncoder().matches(password, userInfo.getPassword())) {
            throw new BadCredentialsException("密码不正确");
        }
        // 还可以加一些其他信息的判断，比如用户账号已停用等判断
        if (userInfo.getStatus().equals("PROHIBIT")){
            throw new LockedException("该用户已被冻结");
        }
        // 角色集合
        Set<GrantedAuthority> authorities = new HashSet<>();
        // 查询用户角色
        //一张表储存了用户id和他的所拥有的权限的id，另一张表储存了对应权限id的权限名。
        //所以查出来是一列权限实体类
       
        List<SysRoleEntity> sysRoleEntityList = sysUserService.selectSysRoleByUserId(userInfo.getUserId());
        for (SysRoleEntity sysRoleEntity: sysRoleEntityList){
            authorities.add(new SimpleGrantedAuthority("ROLE_" + sysRoleEntity.getRoleName()));
        }
        userInfo.setAuthorities(authorities);
        // 进行登录
        //上方所说的轮询并检测是否成功的标志就是看返回的是不是为null,不为null则表明认证成功。
        return new UsernamePasswordAuthenticationToken(userInfo, password, authorities);
    }
    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
```

### 查询用户是否存在 SelfUserDetailsService

```java
public class SelfUserDetailsService implements UserDetailsService {

    @Autowired
    private SysUserService sysUserService;

    /**
     * 查询用户信息
     * @Author Sans
     * @CreateTime 2019/9/13 17:23
     * @Param  username  用户名
     * @Return UserDetails SpringSecurity用户信息
     */
    @Override
    public SelfUserEntity loadUserByUsername(String username) throws UsernameNotFoundException {
        // 查询用户信息
        SysUserEntity sysUserEntity =sysUserService.selectUserByName(username);
        if (sysUserEntity!=null){
            // 组装参数
            SelfUserEntity selfUserEntity = new SelfUserEntity();
            BeanUtils.copyProperties(sysUserEntity,selfUserEntity);
            return selfUserEntity;
        }
        return null;
    }
}
```

### 符合Security标准的用户类 SelfUserEntity

```java
@Data
public class SelfUserEntity implements Serializable, UserDetails {

	private static final long serialVersionUID = 1L;

	/**
	 * 用户ID
	 */
	private Long userId;
	/**
	 * 用户名
	 */
	private String username;
	/**
	 * 密码
	 */
	private String password;
	/**
	 * 状态:NORMAL正常  PROHIBIT禁用
	 */
	private String status;


	/**
	 * 用户角色
	 */
	private Collection<GrantedAuthority> authorities;
	/**
	 * 账户是否过期
	 */
	private boolean isAccountNonExpired = false;
	/**
	 * 账户是否被锁定
	 */
	private boolean isAccountNonLocked = false;
	/**
	 * 证书是否过期
	 */
	private boolean isCredentialsNonExpired = false;
	/**
	 * 账户是否有效
	 */
	private boolean isEnabled = true;


	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}
	@Override
	public boolean isAccountNonExpired() {
		return isAccountNonExpired;
	}
	@Override
	public boolean isAccountNonLocked() {
		return isAccountNonLocked;
	}
	@Override
	public boolean isCredentialsNonExpired() {
		return isCredentialsNonExpired;
	}
	@Override
	public boolean isEnabled() {
		return isEnabled;
	}
}
```

### 登录成功处理类 UserLoginSuccessHandler

```java
@Slf4j
@Component
public class UserLoginSuccessHandler implements AuthenticationSuccessHandler {
    /**
     * 登录成功返回结果
     * @Author Sans
     * @CreateTime 2019/10/3 9:27
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication){
        // 组装JWT
        //在认证处理器部分，将userinfo传入给UsernamePasswordAuthenticationToken作为principal
        SelfUserEntity selfUserEntity =  (SelfUserEntity) authentication.getPrincipal();
        String token = JWTTokenUtil.createAccessToken(selfUserEntity);
        log.info(selfUserEntity.toString());
        token = JWTConfig.tokenPrefix + token;
        // 封装返回参数
        Map<String,Object> resultData = new HashMap<>();
        resultData.put("code","200");
        resultData.put("msg", "登录成功");
        resultData.put("token",token);
        ResultUtil.responseJson(response,resultData);
    }
}
```

### 与JWT有关的工具类 JWTTokenUtil

```java
@Slf4j
public class JWTTokenUtil {

    /**
     * 私有化构造器
     */
    private JWTTokenUtil(){}

    /**
     * 生成Token
     * @Author Sans
     * @CreateTime 2019/10/2 12:16
     * @Param  selfUserEntity 用户安全实体
     * @Return Token
     */
    public static String createAccessToken(SelfUserEntity selfUserEntity){
        // 登陆成功生成JWT
        String token = Jwts.builder()
                // 放入用户名和用户ID
                .setId(selfUserEntity.getUserId()+"")
                // 主题
                .setSubject(selfUserEntity.getUsername())
                // 签发时间
                .setIssuedAt(new Date())
                // 签发者
                .setIssuer("sans")
                // 自定义属性 放入用户拥有权限
            	//重申一遍，多角色的时候，这个属性长[{"authority":"ROLE_USER"},{"authority":"ROLE_ADMIN"}]这样，表明他有两个角色
                .claim("authorities", JSON.toJSONString(selfUserEntity.getAuthorities()))
                // 失效时间
                .setExpiration(new Date(System.currentTimeMillis() + JWTConfig.expiration))
                // 签名算法和密钥
                .signWith(SignatureAlgorithm.HS512, JWTConfig.secret)
                .compact();
        log.info(JSON.toJSONString(selfUserEntity.getAuthorities()));
        return token;
    }
}
```

## 5、JWT+数据库 鉴权部分

上图

<img src="/img/image-20200629141557755.png" alt="image-20200629141557755" style="zoom:80%;" />



用到的类

### hasPermission 鉴权类 UserPermissionEvaluator

```java 
@Component
@Slf4j
public class UserPermissionEvaluator implements PermissionEvaluator {
    @Autowired
    private SysUserService sysUserService;
    /**
     * hasPermission鉴权方法
     * 这里仅仅判断PreAuthorize注解中的权限表达式
     * 实际中可以根据业务需求设计数据库通过targetUrl和permission做更复杂鉴权
     * 当然targetUrl不一定是URL可以是数据Id还可以是管理员标识等,这里根据需求自行设计
     * @Author Sans
     * @CreateTime 2019/10/6 18:25
     * @Param  authentication  用户身份(在使用hasPermission表达式时Authentication参数默认会自动带上)
     * @Param  targetUrl  请求路径
     * @Param  permission 请求路径权限
     * @Return boolean 是否通过
     */
    @Override
    //传入用户安全信息、目标url、需要的权限
    public boolean hasPermission(Authentication authentication, Object targetUrl, Object permission) {
        // 获取用户信息
        SelfUserEntity selfUserEntity =(SelfUserEntity) authentication.getPrincipal();
        Collection<GrantedAuthority> authorities = selfUserEntity.getAuthorities();
        for (GrantedAuthority authority : authorities) {
            log.info(authority.getAuthority());
        }
        // 查询用户权限(这里可以将权限放入缓存中提升效率)
        Set<String> permissions = new HashSet<>();
        //role，权限表，表示有什么权限
        //menu，功能表，表示能做什么
        //role_menu表，表示什么权限能做什么事情
        //user，用户表，表示你是谁
        //user_role表，表示你有什么权限
        //          SELECT DISTINCT m.* FROM sys_user_role ur
        //			LEFT JOIN sys_role_menu rm ON ur.role_id = rm.role_id
        //			LEFT JOIN sys_menu m ON rm.menu_id = m.menu_id
        //		    WHERE ur.user_id = #{userId}
        //通过用户的id，查询他能干什么。
        List<SysMenuEntity> sysMenuEntityList = sysUserService.selectSysMenuByUserId(selfUserEntity.getUserId());
        for (SysMenuEntity sysMenuEntity:sysMenuEntityList) {
            permissions.add(sysMenuEntity.getPermission());
        }
        // 权限对比
        if (permissions.contains(permission.toString())){
            return true;
        }
        return false;
    }
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
```

**详细代码与注释**：[Gitee](https://gitee.com/gukkibokou/spring-boot-security-demo)