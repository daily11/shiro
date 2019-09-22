package com.swust.demo.rbac.util.shiro;

import com.swust.demo.rbac.bean.AclInfo;
import com.swust.demo.rbac.bean.UserInfo;
import com.swust.demo.rbac.service.TreeService;
import com.swust.demo.rbac.service.UserInfoService;
import com.swust.demo.rbac.service.impl.TreeServiceImpl;
import com.swust.demo.rbac.service.impl.UserInfoServiceImpl;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 用户验证
 */
public class UserRealm extends AuthorizingRealm {

    //层级树服务
    TreeService treeService = new TreeServiceImpl();
    //用户服务
    UserInfoService userService = new UserInfoServiceImpl();

    /**
     * 获取授权信息
     * 授权
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {
        UserInfo user = ShiroUtils.getUser();
        System.out.println(user);
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 1 角色加入AuthorizationInfo认证对象
//        info.setRoles(user.getRoles());
        // 2 权限加入AuthorizationInfo认证对象
        //2.1 获取当前用户所有的权限！
        List<AclInfo> userAclList = treeService.userAcls(user.getId());
        if (userAclList != null && userAclList.size() > 0) {
            Set<String> resources = new HashSet<>();
            for (AclInfo aclInfo : userAclList) {
                resources.add(aclInfo.getUrl());
            }
            info.setStringPermissions(resources);
        }
        return info;
    }

    /**
     * 获取身份验证信息
     * 登录认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();
        String password = "";
        if (upToken.getPassword() != null) {
            password = new String(upToken.getPassword());
        }
        UserInfo userInfo = null;
        try {
            userInfo = userService.login(username, password);
            if (userInfo == null) {
                throw new AuthenticationException("用户名或密码错误", new Exception());
            }
        } catch (Exception e) {
            throw new AuthenticationException(e.getMessage(), e);
        }
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(userInfo, password, getName());
        return info;
    }

    /**
     * 清理缓存权限
     */
    public void clearCachedAuthorizationInfo() {
        this.clearCachedAuthorizationInfo(SecurityUtils.getSubject().getPrincipals());
    }
}
