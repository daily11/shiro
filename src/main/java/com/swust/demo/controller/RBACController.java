package com.swust.demo.controller;

import com.swust.demo.rbac.bean.*;
import com.swust.demo.rbac.dto.*;
import com.swust.demo.rbac.service.*;
import com.swust.demo.rbac.service.impl.*;
import com.swust.demo.util.*;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequestMapping("/rbac")
@RestController
public class RBACController {
    //权限模块服务
    AclModuleInfoService aclModuleService = new AclModuleInfoServiceImpl();
    //权限点服务
    AclInfoService aclService = new AclInfoServiceImpl();
    //角色-权限点服务
    RoleAclRelationService roleAclService = new RoleAclRelationServiceImpl();
    //角色服务
    RoleInfoService roleService = new RoleInfoServiceImpl();
    //层级树服务
    TreeService treeService = new TreeServiceImpl();
    //用户组-角色服务
    UsergroupRoleRelationService userRoleService = new UsergroupRoleRelationServiceImpl();
    //用户服务
    UserInfoService userService = new UserInfoServiceImpl();
    //用户组服务
    UsergroupInfoService usergroupInfoService = new UsergroupInfoServiceImpl();

    /**
     * 用户登录
     *
     * @param username
     * @param password
     * @return
     */
    @RequestMapping("/login")
    public Result saveAclModule(String username, String password) {
        try {
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            Subject subject = SecurityUtils.getSubject();
            subject.login(token);
            return new Result(CODE.SUCCESS, "success", "success");
        } catch (AuthenticationException e) {
            e.printStackTrace();
            return new Result(CODE.ERROR, "error", "error");
        }
    }

    /**
     * 保存功能模块
     *
     * @param param
     * @return
     */
    @RequestMapping("/saveAclModule")
//    @RequiresPermissions("/rbac/saveAclModule")
    public Result saveAclModule(@RequestBody AclModuleInfo param) {
        try {
            aclModuleService.save(param);
            return this.findAllAclModule();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 删除功能模块
     *
     * @param aclModuleId
     * @return
     */
    @RequestMapping("/deleteAclModule")
//    @RequiresPermissions("/rbac/deleteAclModule")
    public Result deleteAclModule(Long aclModuleId) {
        try {
            aclModuleService.delete(aclModuleId);
            return this.findAllAclModule();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 更新功能模块
     *
     * @param aclModule
     * @return
     */
    @RequestMapping("/updateAclModule")
//    @RequiresPermissions("/rbac/updateAclModule")
    public Result updateAclModule(@RequestBody AclModuleInfo aclModule) {
        try {
            aclModuleService.update(aclModule);
            return this.findAllAclModule();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询所有的功能模块
     *
     * @return
     */
    @RequestMapping("/findAllAclModule")
//    @RequiresPermissions("/rbac/findAllAclModule")
    public Result findAllAclModule() {
        try {
            List<AclModuleInfo> list = aclModuleService.select();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据功能模块id查询功能模块
     *
     * @param aclModuleId
     * @return
     */
    @RequestMapping("/findAclModuleById")
//    @RequiresPermissions("/rbac/findAclModuleById")
    public Result findAclModuleById(Long aclModuleId) {
        try {
            AclModuleInfo aclModule = aclModuleService.selectById(aclModuleId);
            return new Result(200, aclModule, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 保存功能点
     * <p>
     * 超级管理员默认拥有添加的功能点权限，因此除了新增功能记录，还需要增加角色-功能点关联记录
     *
     * @param param 功能点记录
     * @return
     */
    @RequestMapping("/saveAcl")
//    @RequiresPermissions("/rbac/saveAcl")
    public Result saveAcl(@RequestBody AclInfo param) {
        long roleId = 60;//超级管理员对应的id
        try {
            //1 保存功能点
            aclService.save(param);
            //2 超级管理员【角色】添加该功能点权限
            //2.1 查询功能点集合
            List<AclInfo> aclList = aclService.select();
            //2.2 根据功能点名称，遍历功能点集合，找到功能点id
            for (int i = 0; i < aclList.size(); i++) {
                AclInfo acl = aclList.get(i);
                if (acl.getName().equals(param.getName())) {
                    param.setId(acl.getId());
                    break;
                }
            }
            //2.3 查询角色集合
            List<RoleInfo> roleList = roleService.select();
            //2.4 遍历角色集合，找到“超级管理员”角色对应的id
            for (int i = 0; i < roleList.size(); i++) {
                RoleInfo role = roleList.get(i);
                if (role.getName().equals("超级管理员")) {
                    roleId = role.getId();
                    break;
                }
            }
            //2.5 添加角色功能关联记录
            RoleAclRelation roleAclParam = RoleAclRelation.builder()
                    .aclId(param.getId())
                    .roleId(roleId)
                    .build();
            roleAclService.save(roleAclParam);

            return this.findAllAcl();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 删除功能点
     *
     * @param aclId
     * @return
     */
    @RequestMapping("/deleteAcl")
//    @RequiresPermissions("/rbac/deleteAcl")
    public Result deleteAcl(Long aclId) {
        try {
            aclService.delete(aclId);
            return this.findAllAcl();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询所有功能点
     *
     * @return
     */
    @RequestMapping("/findAllAcl")
//    @RequiresPermissions("/rbac/findAllAcl")
    public Result findAllAcl() {
        try {
            List<AclInfo> list = aclService.select();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据功能点id查询功能点
     *
     * @param aclid
     * @return
     */
    @RequestMapping("/findAclById")
//    @RequiresPermissions("/rbac/findAclById")
    public Result findAclById(Long aclid) {
        try {
            AclInfo acl = aclService.selectById(aclid);
            return new Result(200, acl, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 更新功能点
     *
     * @param acl
     * @return
     */
    @RequestMapping("/updateAcl")
//    @RequiresPermissions("/rbac/updateAcl")
    public Result updateAcl(@RequestBody AclInfo acl) {
        try {
            aclService.update(acl);
            return this.findAllAcl();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 保存角色功能关联记录
     *
     * @param param
     * @return
     */
    @RequestMapping("/saveRoleAcl")
//    @RequiresPermissions("/rbac/saveRoleAcl")
    public Result saveRoleAcl(@RequestBody RoleAclRelation param) {
        try {
            roleAclService.save(param);
            return this.findAllRoleAcl();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 删除角色功能
     *
     * @param roleAclId
     * @return
     */
    @RequestMapping("/deleteRoleAcl")
//    @RequiresPermissions("/rbac/deleteRoleAcl")
    public Result deleteRoleAcl(Long roleAclId) {
        try {
            roleAclService.delete(roleAclId);
            return this.findAllRoleAcl();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询所有的角色功能
     *
     * @return
     */
    @RequestMapping("/findAllRoleAcl")
//    @RequiresPermissions("/rbac/findAllRoleAcl")
    public Result findAllRoleAcl() {
        try {
            List<RoleAclRelation> list = roleAclService.select();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据角色功能id查询角色功能
     *
     * @param roleAclId
     * @return
     */
    @RequestMapping("/findRoleAclById")
//    @RequiresPermissions("/rbac/findRoleAclById")
    public Result findRoleAclById(Long roleAclId) {
        try {
            RoleAclRelation roleAcl = roleAclService.selectById(roleAclId);
            return new Result(200, roleAcl, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 更新角色功能
     *
     * @param roleAcl
     * @return
     */
    @RequestMapping("/updateRoleAcl")
//    @RequiresPermissions("/rbac/updateRoleAcl")
    public Result updateRoleAcl(@RequestBody RoleAclRelation roleAcl) {
        try {
            roleAclService.update(roleAcl);
            return this.findAllRoleAcl();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 保存角色
     *
     * @param param
     * @return
     */
    @RequestMapping("/saveRole")
//    @RequiresPermissions("/rbac/saveRole")
    public Result saveRole(@RequestBody RoleInfo param) {
        try {
            roleService.save(param);
            return this.findAllRole();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 删除角色
     *
     * @param roleId
     * @return
     */
    @RequestMapping("/deleteRole")
//    @RequiresPermissions("/rbac/deleteRole")
    public Result deleteRole(Long roleId) {
        try {
            roleService.delete(roleId);
            return this.findAllRole();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据角色查询角色功能
     *
     * @param roleName
     * @return
     */
    @RequestMapping("/fidRoleAclByRolename")
//    @RequiresPermissions("/rbac/fidRoleAclByRolename")
    public Result fidRoleAclByRolename(String roleName) {
        try {

            return new Result(200, treeService.selectRoleAclViewParam(roleName), "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询角色
     *
     * @return
     */
    @RequestMapping("/findAllRole")
//    @RequiresPermissions("/rbac/findAllRole")
    public Result findAllRole() {
        try {
            List<RoleInfo> list = roleService.select();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据id查询角色
     *
     * @param roleId
     * @return
     */
    @RequestMapping("/findRoleById")
//    @RequiresPermissions("/rbac/findRoleById")
    public Result findRoleById(Long roleId) {
        try {
            RoleInfo role = roleService.selectById(roleId);
            return new Result(200, role, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 更新角色
     *
     * @param role
     * @return
     */
    @RequestMapping("/updateRole")
//    @RequiresPermissions("/rbac/updateRole")
    public Result updateRole(@RequestBody RoleInfo role) {
        try {
            roleService.update(role);
            return this.findAllRole();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询层级树
     *
     * @return
     */
    @RequestMapping("/aclModuleTree")
//    @RequiresPermissions("/rbac/aclModuleTree")
    public Result aclModuleTree() {
        try {
            List<AclModuleLevelDto> list = treeService.aclModuleTree();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询角色权限模块层级树
     *
     * @param roleName 角色名
     * @return
     */
    @RequestMapping("/aclModuleTreeByRolename")
//    @RequiresPermissions("/rbac/aclModuleTreeByRolename")
    public Result aclModuleTreeByRolename(String roleName) {
        try {
            List<AclModuleLevelDto> list = treeService.aclModuleTreeByRolename(roleName);
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据用户id及用户名查询权限层级树
     *
     * @param userid
     * @param name
     * @return
     */
    @RequestMapping("/aclModuleTreeByUserIdAndname")
//    @RequiresPermissions("/rbac/aclModuleTreeByUserIdAndname")
    public Result aclModuleTreeByUserIdAndname(int userid, String name) {
        try {
            List<AclModuleLevelDto> list = treeService.aclModuleTreeByUserIdAndname(userid, name);
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据id查询用户权限
     *
     * @param id
     * @return
     */
    @RequestMapping("/userAcls")
//    @RequiresPermissions("/rbac/userAcls")
    public Result userAcls(Long id) {
        try {
            List<AclInfo> list = treeService.userAcls(id);
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询系统预定义给用户对应角色的权限
     *
     * @param userid 用户di
     * @param name   用户名称【同时也是角色名称】
     * @return
     */
    @RequestMapping("/findUserAclsBySystem")
//    @RequiresPermissions("/rbac/findUserAclsBySystem")
    public Result findUserAclsBySystem(int userid, String name) {
        try {
            List<AclInfo> list = treeService.findUserAclsBySystem(userid, name);
            return new Result(200, list, "成功");
        } catch (Exception e) {
            e.printStackTrace();
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询用户自己的，非系统预定义的权限
     *
     * @param userid 用户di
     * @param name   用户名称【同时也是角色名称】
     * @return
     */
    @RequestMapping("/findUserAclsBySingle")
//    @RequiresPermissions("/rbac/findUserAclsBySingle")
    public Result findUserAclsBySingle(int userid, String name) {
        try {
            List<AclInfo> list = treeService.findUserAclsBySingle(userid, name);
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 保存用户组角色关联记录
     *
     * @param param
     * @return
     */
    @RequestMapping("/saveUserRole")
//    @RequiresPermissions("/rbac/saveUserRole")
    public Result saveUserRole(@RequestBody UsergroupRoleRelation param) {
        try {
            userRoleService.save(param);
            return this.findAllUserRole();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 绑定用户组-角色信息
     *
     * @param roleId     角色id
     * @param userIdList 需要绑定的用户组id集合
     * @return
     */
    @RequestMapping("/bindUserRole")
//    @RequiresPermissions("/rbac/bindUserRole")
    public Result bindUserRole(Long roleId, Long[] userIdList) {
        try {
            userRoleService.bindUserRole(roleId, userIdList);
            return this.findAllUserRole();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 删除用户组角色关联记录
     *
     * @param userRoleId
     * @return
     */
    @RequestMapping("/deleteUserRole")
//    @RequiresPermissions("/rbac/deleteUserRole")
    public Result deleteUserRole(Long userRoleId) {
        try {
            userRoleService.delete(userRoleId);
            return this.findAllUserRole();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询用户组角色关联记录
     *
     * @return
     */
    @RequestMapping("/findAllUserRole")
//    @RequiresPermissions("/rbac/findAllUserRole")
    public Result findAllUserRole() {
        try {
            List<UsergroupRoleRelation> list = userRoleService.select();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据id查询用户组角色关联记录
     *
     * @param userRoleId
     * @return
     */
    @RequestMapping("/findUserRoleById")
//    @RequiresPermissions("/rbac/findUserRoleById")
    public Result findUserRoleById(Long userRoleId) {
        try {
            UsergroupRoleRelation userRole = userRoleService.selectById(userRoleId);
            return new Result(200, userRole, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 更新用户组角色关联记录
     *
     * @param userRole
     * @return
     */
    @RequestMapping("/updateUserRole")
//    @RequiresPermissions("/rbac/updateUserRole")
    public Result updateUserRole(@RequestBody UsergroupRoleRelation userRole) {
        try {
            userRoleService.update(userRole);
            return this.findAllUserRole();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 保存用户组
     *
     * @param param
     * @return
     */
    @RequestMapping("/saveUsergroup")
//    @RequiresPermissions("/rbac/saveUsergroup")
    public Result saveUsergroup(@RequestBody UsergroupInfo param) {
        try {
            usergroupInfoService.save(param);
            return this.findAllUser();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 删除用户组
     *
     * @param usergroupId
     * @return
     */
    @RequestMapping("/deleteUsergroup")
//    @RequiresPermissions("/rbac/deleteUsergroup")
    public Result deleteUsergroup(Long usergroupId) {
        try {
            usergroupInfoService.delete(usergroupId);
            return this.findAllUser();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询所有的用户组信息
     *
     * @return
     */
    @RequestMapping("/findAllUsergroup")
//    @RequiresPermissions("/rbac/findAllUsergroup")
    public Result findAllUsergroup() {
        try {
            List<UsergroupInfo> list = usergroupInfoService.select();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据id查询用户组
     *
     * @param usergroupId
     * @return
     */
    @RequestMapping("/findUsergroupById")
//    @RequiresPermissions("/rbac/findUsergroupById")
    public Result findUsergroupById(Long usergroupId) {
        try {
            UsergroupInfo user = usergroupInfoService.selectById(usergroupId);
            return new Result(200, user, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 更新用户组
     *
     * @param usergroupInfo
     * @return
     */
    @RequestMapping("/updateUsergroup")
//    @RequiresPermissions("/rbac/updateUsergroup")
    public Result updateUser(@RequestBody UsergroupInfo usergroupInfo) {
        try {
            usergroupInfoService.update(usergroupInfo);
            return this.findAllUser();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }


    /**
     * 保存用户
     *
     * @param param
     * @return
     */
    @RequestMapping("/saveUser")
//    @RequiresPermissions("/rbac/saveUser")
    public Result saveUser(@RequestBody UserInfo param) {
        try {
            userService.save(param);
            return this.findAllUser();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 删除用户
     *
     * @param userId
     * @return
     */
    @RequestMapping("/deleteUser")
//    @RequiresPermissions("/rbac/deleteUser")
    public Result deleteUser(Long userId) {
        try {
            userService.delete(userId);
            return this.findAllUser();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 查询用户
     *
     * @return
     */
    @RequestMapping("/findAllUser")
//    @RequiresPermissions("/rbac/findAllUser")
    public Result findAllUser() {
        try {
            List<UserInfo> list = userService.select();
            return new Result(200, list, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 根据id查询用户
     *
     * @param userId
     * @return
     */
    @RequestMapping("/findUserById")
//    @RequiresPermissions("/rbac/findUserById")
    public Result findUserById(Long userId) {
        try {
            UserInfo user = userService.selectById(userId);
            return new Result(200, user, "成功");
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 更新用户
     *
     * @param user
     * @return
     */
    @RequestMapping("/updateUser")
//    @RequiresPermissions("/rbac/updateUser")
    public Result updateUser(@RequestBody UserInfo user) {
        try {
            userService.update(user);
            return this.findAllUser();
        } catch (Exception e) {
            return new Result(500, e.getStackTrace(), "失败");
        }
    }

    /**
     * 功能模块与功能点绑定
     *
     * @param ids         角色id集合
     * @param aclModuleId 角色模块id
     * @return
     */
    @RequestMapping("/bondAclModule")
//    @RequiresPermissions("/rbac/bondAclModule")
    public Result bondAclModule(Long[] ids, Long aclModuleId) {
        if (ids == null || ids.length < 1 || aclModuleId == null)
            return new Result(500, null, "输入参数错误");
        aclService.updateSysAcl1(ids, aclModuleId);
        return this.findAllAcl();
    }

}
