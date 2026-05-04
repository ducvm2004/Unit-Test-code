package com.cvconnect.service.impl;

import com.cvconnect.entity.Menu;
import com.cvconnect.entity.Role;
import com.cvconnect.entity.RoleMenu;
import com.cvconnect.entity.RoleUser;
import com.cvconnect.entity.User;
import com.cvconnect.enums.PermissionType;
import com.cvconnect.repository.MenuRepository;
import com.cvconnect.repository.RoleMenuRepository;
import com.cvconnect.repository.RoleRepository;
import com.cvconnect.repository.RoleUserRepository;
import com.cvconnect.repository.UserRepository;
import com.cvconnect.service.RoleMenuService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class RoleMenuServiceIntegrationTest {

    @Autowired
    private RoleMenuService roleMenuService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private MenuRepository menuRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleUserRepository roleUserRepository;

    @Autowired
    private RoleMenuRepository roleMenuRepository;

    private User user;

    @BeforeEach
    void setup() {
        user = new User();
        user.setUsername("int_test_user");
        user.setEmail("int_user@example.com");
        user.setFullName("Int Test User");
        user.setAccessMethod("LOCAL");
        user.setIsActive(true);
        user.setIsEmailVerified(true);
        user = userRepository.save(user);
    }

    private boolean hasPermission(Map<String, List<String>> authorities, String menuCode, PermissionType action) {
        return authorities.getOrDefault(menuCode, List.of()).contains(action.name());
    }

    @Test
    @Transactional
    @Rollback
    void TC01_only_view() {
        Role role = new Role(); role.setCode("HR_ADMIN"); role.setName("HR"); role.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedRole = roleRepository.save(role);
        String menuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        Menu menu = new Menu(); menu.setCode(menuCode); menu.setLabel("User"); menu.setSortOrder(1); menu = menuRepository.save(menu);
        RoleUser ru = new RoleUser(); ru.setUserId(user.getId()); ru.setRoleId(savedRole.getId()); roleUserRepository.save(ru);
        RoleMenu rm = new RoleMenu(); rm.setRoleId(savedRole.getId()); rm.setMenuId(menu.getId()); rm.setPermission("VIEW"); roleMenuRepository.save(rm);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("HR_ADMIN"));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @Transactional
    @Rollback
    void TC02_only_update() {
        Role role = new Role(); role.setCode("HR_ADMIN"); role.setName("HR"); role.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedRole = roleRepository.save(role);
        String menuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        Menu menu = new Menu(); menu.setCode(menuCode); menu.setLabel("User"); menu.setSortOrder(1); menu = menuRepository.save(menu);
        RoleUser ru = new RoleUser(); ru.setUserId(user.getId()); ru.setRoleId(savedRole.getId()); roleUserRepository.save(ru);
        RoleMenu rm = new RoleMenu(); rm.setRoleId(savedRole.getId()); rm.setMenuId(menu.getId()); rm.setPermission("UPDATE"); roleMenuRepository.save(rm);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("HR_ADMIN"));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @Transactional
    @Rollback
    void TC03_only_delete() {
        Role role = new Role(); role.setCode("HR_ADMIN"); role.setName("HR"); role.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedRole = roleRepository.save(role);
        String menuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        Menu menu = new Menu(); menu.setCode(menuCode); menu.setLabel("User"); menu.setSortOrder(1); menu = menuRepository.save(menu);
        RoleUser ru = new RoleUser(); ru.setUserId(user.getId()); ru.setRoleId(savedRole.getId()); roleUserRepository.save(ru);
        RoleMenu rm = new RoleMenu(); rm.setRoleId(savedRole.getId()); rm.setMenuId(menu.getId()); rm.setPermission("DELETE"); roleMenuRepository.save(rm);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("HR_ADMIN"));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @Transactional
    @Rollback
    void TC04_only_export() {
        Role role = new Role(); role.setCode("HR_ADMIN"); role.setName("HR"); role.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedRole = roleRepository.save(role);
        String menuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        Menu menu = new Menu(); menu.setCode(menuCode); menu.setLabel("User"); menu.setSortOrder(1); menu = menuRepository.save(menu);
        RoleUser ru = new RoleUser(); ru.setUserId(user.getId()); ru.setRoleId(savedRole.getId()); roleUserRepository.save(ru);
        RoleMenu rm = new RoleMenu(); rm.setRoleId(savedRole.getId()); rm.setMenuId(menu.getId()); rm.setPermission("EXPORT"); roleMenuRepository.save(rm);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("HR_ADMIN"));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @Transactional
    @Rollback
    void TC05_viewer_only_scope() {
        Role role = new Role(); role.setCode("VIEWER"); role.setName("Viewer"); role.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedRole = roleRepository.save(role);
        String menuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        Menu menu = new Menu(); menu.setCode(menuCode); menu.setLabel("User"); menu.setSortOrder(1); menu = menuRepository.save(menu);
        RoleUser ru = new RoleUser(); ru.setUserId(user.getId()); ru.setRoleId(savedRole.getId()); roleUserRepository.save(ru);
        RoleMenu rm = new RoleMenu(); rm.setRoleId(savedRole.getId()); rm.setMenuId(menu.getId()); rm.setPermission("VIEW"); roleMenuRepository.save(rm);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("VIEWER"));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @Transactional
    @Rollback
    void TC06_merge_permissions_two_roles_same_menu() {
        Role a = new Role(); a.setCode("ROLE_A"); a.setName("A"); a.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedA = roleRepository.save(a);
        Role b = new Role(); b.setCode("ROLE_B"); b.setName("B"); b.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedB = roleRepository.save(b);
        String menuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        Menu menu = new Menu(); menu.setCode(menuCode); menu.setLabel("User"); menu.setSortOrder(1); menu = menuRepository.save(menu);
        RoleUser ra = new RoleUser(); ra.setUserId(user.getId()); ra.setRoleId(savedA.getId()); roleUserRepository.save(ra);
        RoleUser rb = new RoleUser(); rb.setUserId(user.getId()); rb.setRoleId(savedB.getId()); roleUserRepository.save(rb);
        RoleMenu rmA = new RoleMenu(); rmA.setRoleId(savedA.getId()); rmA.setMenuId(menu.getId()); rmA.setPermission("VIEW"); roleMenuRepository.save(rmA);
        RoleMenu rmB = new RoleMenu(); rmB.setRoleId(savedB.getId()); rmB.setMenuId(menu.getId()); rmB.setPermission("EXPORT"); roleMenuRepository.save(rmB);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("ROLE_A","ROLE_B"));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @Transactional
    @Rollback
    void TC07_duplicate_permissions_two_roles_same_menu() {
        Role a = new Role(); a.setCode("ROLE_A"); a.setName("A"); a.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedA = roleRepository.save(a);
        Role b = new Role(); b.setCode("ROLE_B"); b.setName("B"); b.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedB = roleRepository.save(b);
        String menuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        Menu menu = new Menu(); menu.setCode(menuCode); menu.setLabel("User"); menu.setSortOrder(1); menu = menuRepository.save(menu);
        RoleUser ra = new RoleUser(); ra.setUserId(user.getId()); ra.setRoleId(savedA.getId()); roleUserRepository.save(ra);
        RoleUser rb = new RoleUser(); rb.setUserId(user.getId()); rb.setRoleId(savedB.getId()); roleUserRepository.save(rb);
        RoleMenu rmA = new RoleMenu(); rmA.setRoleId(savedA.getId()); rmA.setMenuId(menu.getId()); rmA.setPermission("VIEW"); roleMenuRepository.save(rmA);
        RoleMenu rmB = new RoleMenu(); rmB.setRoleId(savedB.getId()); rmB.setMenuId(menu.getId()); rmB.setPermission("VIEW"); roleMenuRepository.save(rmB);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("ROLE_A","ROLE_B"));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @Transactional
    @Rollback
    void TC08_not_mix_permissions_across_menus() {
        Role a = new Role(); a.setCode("ROLE_A"); a.setName("A"); a.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedA = roleRepository.save(a);
        Role b = new Role(); b.setCode("ROLE_B"); b.setName("B"); b.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); Role savedB = roleRepository.save(b);
        String userMenuCode = "USER_" + UUID.randomUUID().toString().substring(0,8);
        String roleMenuCode = "ROLE_" + UUID.randomUUID().toString().substring(0,8);
        Menu userMenu = new Menu(); userMenu.setCode(userMenuCode); userMenu.setLabel("User"); userMenu.setSortOrder(1); userMenu = menuRepository.save(userMenu);
        Menu roleMenu = new Menu(); roleMenu.setCode(roleMenuCode); roleMenu.setLabel("Role"); roleMenu.setSortOrder(2); roleMenu = menuRepository.save(roleMenu);
        RoleUser ra = new RoleUser(); ra.setUserId(user.getId()); ra.setRoleId(savedA.getId()); roleUserRepository.save(ra);
        RoleUser rb = new RoleUser(); rb.setUserId(user.getId()); rb.setRoleId(savedB.getId()); roleUserRepository.save(rb);
        RoleMenu rmA = new RoleMenu(); rmA.setRoleId(savedA.getId()); rmA.setMenuId(userMenu.getId()); rmA.setPermission("VIEW"); roleMenuRepository.save(rmA);
        RoleMenu rmB = new RoleMenu(); rmB.setRoleId(savedB.getId()); rmB.setMenuId(roleMenu.getId()); rmB.setPermission("DELETE"); roleMenuRepository.save(rmB);

        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("ROLE_A","ROLE_B"));
        assertTrue(hasPermission(authorities, userMenuCode, PermissionType.VIEW));
        assertFalse(hasPermission(authorities, userMenuCode, PermissionType.DELETE));
        assertTrue(hasPermission(authorities, roleMenuCode, PermissionType.DELETE));
        assertFalse(hasPermission(authorities, roleMenuCode, PermissionType.VIEW));
    }

    @Test
    @Transactional
    @Rollback
    void TC09_stale_role_returns_empty() {
        // create a role but do not create role_menu entries for it
        Role stale = new Role(); stale.setCode("STALE_ROLE"); stale.setName("Stale"); stale.setMemberType(com.cvconnect.enums.MemberType.MANAGEMENT); stale = roleRepository.save(stale);
        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("STALE_ROLE"));
        assertTrue(authorities.isEmpty());
    }

    @Test
    @Transactional
    @Rollback
    void TC10_missing_role_returns_empty() {
        // do not create any role with code MISSING_ROLE
        Map<String, List<String>> authorities = roleMenuService.getAuthorities(user.getId(), List.of("MISSING_ROLE"));
        assertTrue(authorities.isEmpty());
    }
}
