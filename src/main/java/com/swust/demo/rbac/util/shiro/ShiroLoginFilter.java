/**
 * Copyright (C), 2018-2018
 * FileName: ShiroLoginFilter
 * Author:   lihui
 * Date:     2018-12-27 10:27
 * Description:
 * History:
 * <author>          <time>          <version>          <desc>
 * 作者姓名           修改时间           版本号              描述
 */
package com.swust.demo.rbac.util.shiro;

import com.swust.demo.rbac.bean.UserInfo;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.filter.AccessControlFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 〈功能简述〉<br>
 * 〈〉
 *
 * @author lihui
 * @create 2018-12-27
 * @since 1.0.0
 */
public class ShiroLoginFilter extends AccessControlFilter {
    final static Class<ShiroLoginFilter> CLASS = ShiroLoginFilter.class;

    /**
     * 判断是否允许
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request,
                                      ServletResponse response, Object mappedValue) throws Exception {
        UserInfo userInfo = (UserInfo)SecurityUtils.getSubject().getPrincipal();
        if(null != userInfo || isLoginRequest(request, response))
        {
            return Boolean.TRUE;
        }
        return Boolean.FALSE;
    }


    /**
     * 验证失败
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response)
            throws Exception {
        //保存Request和Response 到登录后的链接
        redirectToLogin(request, response);
        return Boolean.FALSE;
    }

    /**
     * 返回未登录信息
     */
    @Override
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        Map<String, String> resultMap = new HashMap<>();
        resultMap.put("login_status", "505");
        resultMap.put("msg", "\u5F53\u524D\u7528\u6237\u6CA1\u6709\u767B\u5F55\uFF01");//当前用户没有登录！
        resultMap.put("code", "505");
        resultMap.put("data", "\u5F53\u524D\u7528\u6237\u6CA1\u6709\u767B\u5F55\uFF01");//当前用户没有登录！
        response.getWriter().print(resultMap.toString());
    }
}
