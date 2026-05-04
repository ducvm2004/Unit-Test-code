package com.cvconnect.service.impl;

import com.cvconnect.constant.Constants;
import com.cvconnect.entity.Role;
import com.cvconnect.entity.RoleUser;
import com.cvconnect.entity.User;
import com.cvconnect.enums.MemberType;
import com.cvconnect.enums.UserErrorCode;
import com.cvconnect.repository.RoleRepository;
import com.cvconnect.repository.RoleUserRepository;
import com.cvconnect.repository.UserRepository;
import com.cvconnect.service.UserService;
import nmquan.commonlib.exception.AppException;
import nmquan.commonlib.utils.WebUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@Transactional
public class UserServiceIntegrationTest {

    @Autowired
    private UserService userService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleUserRepository roleUserRepository;

    /**
     * Helper method giúp lấy Role SYSTEM_ADMIN hiện có hoặc tạo mới.
     * Giải quyết lỗi: Duplicate entry 'SYSTEM_ADMIN'
     */
    private Role getOrCreateSystemAdminRole() {
        Role existingRole = roleRepository.findByCode(Constants.RoleCode.SYSTEM_ADMIN);
        if (existingRole != null) {
            return existingRole;
        }

        Role newRole = new Role();
        newRole.setCode(Constants.RoleCode.SYSTEM_ADMIN);
        newRole.setName("System Admin");
        newRole.setMemberType(MemberType.MANAGEMENT);
        newRole.setIsActive(true);
        newRole.setIsDeleted(false);
        return roleRepository.save(newRole);
    }

    @Test
    @Rollback
    void retrieveAdminSystemRole_shouldRollbackWhenLastAdmin() {
        //TC10: Kiểm tra không cho phép xóa Admin cuối cùng
        // 0. Xóa sạch bảng trung gian để đảm bảo "target" là Admin DUY NHẤT trong hệ thống
        roleUserRepository.deleteAll();

        // 1. Chuẩn bị Role
        Role savedRole = getOrCreateSystemAdminRole();

        // 2. Tạo User mục tiêu (Admin duy nhất)
        User target = new User();
        String suffix = String.valueOf(System.nanoTime());
        target.setUsername("target_admin_" + suffix);
        target.setEmail("target_" + suffix + "@example.com");
        target.setFullName("Target Admin");
        target.setAccessMethod("LOCAL");
        target.setIsActive(true);
        target.setIsEmailVerified(true);
        User savedTarget = userRepository.save(target);

        // 3. Gán quyền Admin cho User đó
        RoleUser ru = new RoleUser();
        ru.setUserId(savedTarget.getId());
        ru.setRoleId(savedRole.getId());
        roleUserRepository.save(ru);

        // 4. Tạo User thực hiện (Actor)
        User actor = new User();
        actor.setUsername("actor_" + suffix);
        actor.setEmail("actor_" + suffix + "@example.com");
        actor.setFullName("Actor User");
        actor.setAccessMethod("LOCAL");
        actor.setIsActive(true);
        actor.setIsEmailVerified(true);
        User savedActor = userRepository.save(actor);

        // 5. Kiểm tra logic: Không cho phép xóa Admin cuối cùng
        try (MockedStatic<WebUtils> web = Mockito.mockStatic(WebUtils.class)) {
            web.when(WebUtils::getCurrentUserId).thenReturn(savedActor.getId());

            AppException ex = assertThrows(AppException.class,
                    () -> userService.retrieveAdminSystemRole(savedTarget.getId()),
                    "Phải ném AppException khi xóa Admin cuối cùng");

            assertEquals(UserErrorCode.LAST_SYSTEM_ADMIN_CANNOT_BE_REMOVED, ex.getErrorCode());
        }
    }

    @Test
    @Rollback
    void retrieveAdminSystemRole_shouldNotAllowRemovingOwnAdminRole() {
        //TC11: Kiểm tra không cho phép tự xóa quyền Admin của chính mình
        // 1. Chuẩn bị Role
        Role savedRole = getOrCreateSystemAdminRole();

        // 2. Tạo User (vừa là người xóa, vừa là người bị xóa)
        User user = new User();
        String suffix = String.valueOf(System.nanoTime());
        user.setUsername("self_admin_" + suffix);
        user.setEmail("self_" + suffix + "@example.com");
        user.setFullName("Self Admin");
        user.setAccessMethod("LOCAL");
        user.setIsActive(true);
        user.setIsEmailVerified(true);
        User savedUser = userRepository.save(user);

        // 3. Gán quyền
        RoleUser ru = new RoleUser();
        ru.setUserId(savedUser.getId());
        ru.setRoleId(savedRole.getId());
        roleUserRepository.save(ru);

        // 4. Kiểm tra logic: Không cho phép tự xóa quyền Admin của chính mình
        try (MockedStatic<WebUtils> web = Mockito.mockStatic(WebUtils.class)) {
            web.when(WebUtils::getCurrentUserId).thenReturn(savedUser.getId());

            AppException ex = assertThrows(AppException.class,
                    () -> userService.retrieveAdminSystemRole(savedUser.getId()),
                    "Phải ném AppException khi tự xóa quyền của mình");

            assertEquals(UserErrorCode.CANNOT_REMOVE_OWN_SYSTEM_ADMIN_ROLE, ex.getErrorCode());
        }
    }
}
