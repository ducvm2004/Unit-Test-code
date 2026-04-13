package com.cvconnect.service.impl;

import com.cvconnect.constant.Constants;
import com.cvconnect.dto.role.RoleDto;
import com.cvconnect.dto.roleMenu.RoleMenuProjection;
import com.cvconnect.dto.roleUser.RoleUserDto;
import com.cvconnect.entity.User;
import com.cvconnect.enums.PermissionType;
import com.cvconnect.enums.UserErrorCode;
import com.cvconnect.repository.RoleMenuRepository;
import com.cvconnect.repository.UserRepository;
import com.cvconnect.service.AuthService;
import com.cvconnect.service.CandidateService;
import com.cvconnect.service.FailedRollbackService;
import com.cvconnect.service.ManagementMemberService;
import com.cvconnect.service.OrgMemberService;
import com.cvconnect.service.RoleService;
import com.cvconnect.service.RoleUserService;
import com.cvconnect.utils.ServiceUtils;
import nmquan.commonlib.exception.AppException;
import nmquan.commonlib.utils.WebUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleMenuServiceImplTest {

    // -----------------------------
    // Nhóm test gom quyền (permission)
    // -----------------------------
    // Các test dưới đây kiểm tra cách RoleMenuServiceImpl chuyển dữ liệu
    // role-menu thành tập authorities theo từng action (VIEW/UPDATE/DELETE/EXPORT).

    @Mock
    private RoleMenuRepository roleMenuRepository;

    @InjectMocks
    private RoleMenuServiceImpl roleMenuService;

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private RoleUserService roleUserService;
    @Mock
    private CandidateService candidateService;
    @Mock
    private ManagementMemberService managementMemberService;
    @Mock
    private OrgMemberService orgMemberService;
    @Mock
    private RoleService roleService;
    @Mock
    private com.cvconnect.common.RestTemplateClient restTemplateClient;
    @Mock
    private ServiceUtils serviceUtils;
    @Mock
    private AuthService authService;
    @Mock
    private FailedRollbackService failedRollbackService;

    @InjectMocks
    private UserServiceImpl userService;

    @Test
    @DisplayName("checkPermission theo role + action VIEW/UPDATE/DELETE/EXPORT")
    void checkPermissionByRoleAndAction_shouldSupportAllActions() {
        // TC01
        // Arrange: giả lập 1 menu có đầy đủ 4 quyền.
        Long userId = 100L;
        String menuCode = "USER";

        RoleMenuProjection projection = mock(RoleMenuProjection.class);
        when(projection.getMenuCode()).thenReturn(menuCode);
        when(projection.getPermission()).thenReturn("VIEW,UPDATE,DELETE,EXPORT");

        when(roleMenuRepository.findAuthoritiesByUserId(userId, List.of("HR_ADMIN")))
                .thenReturn(List.of(projection));

        // Act: tạo authorities từ dữ liệu projection trả về từ repository.
        Map<String, List<String>> authorities = roleMenuService.getAuthorities(userId, List.of("HR_ADMIN"));

        // Assert: menu USER phải chứa đủ các action mong đợi.
        assertTrue(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @DisplayName("Lọc theo phạm vi quyền: role chỉ có VIEW không được UPDATE/DELETE/EXPORT")
    void shouldFilterDataByPermissionScope_viewOnlyRole() {
        // TC02
        // Arrange: role chỉ có quyền VIEW trên menu mục tiêu.
        Long userId = 101L;
        String menuCode = "USER";

        RoleMenuProjection projection = mock(RoleMenuProjection.class);
        when(projection.getMenuCode()).thenReturn(menuCode);
        when(projection.getPermission()).thenReturn("VIEW");

        when(roleMenuRepository.findAuthoritiesByUserId(userId, List.of("VIEWER")))
                .thenReturn(List.of(projection));

        // Act: tạo authorities cho role VIEWER.
        Map<String, List<String>> authorities = roleMenuService.getAuthorities(userId, List.of("VIEWER"));

        // Assert: chỉ có VIEW, các quyền còn lại phải không tồn tại.
        assertTrue(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.UPDATE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.DELETE));
        assertFalse(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @DisplayName("Thiếu 1 permission ở role A nhưng được role B bù quyền")
    void shouldMergePermissionsWhenAnotherRoleCompensates() {
        // TC03
        // Arrange: role A có VIEW, role B có EXPORT trên cùng menu.
        Long userId = 102L;
        String menuCode = "USER";

        RoleMenuProjection roleAProjection = mock(RoleMenuProjection.class);
        when(roleAProjection.getMenuCode()).thenReturn(menuCode);
        when(roleAProjection.getPermission()).thenReturn("VIEW");

        RoleMenuProjection roleBProjection = mock(RoleMenuProjection.class);
        when(roleBProjection.getMenuCode()).thenReturn(menuCode);
        when(roleBProjection.getPermission()).thenReturn("EXPORT");

        when(roleMenuRepository.findAuthoritiesByUserId(userId, List.of("ROLE_A", "ROLE_B")))
                .thenReturn(List.of(roleAProjection, roleBProjection));

        // Act: authorities được gộp từ cả hai role.
        Map<String, List<String>> authorities = roleMenuService.getAuthorities(userId, List.of("ROLE_A", "ROLE_B"));

        // Assert: người dùng nhận được quyền bù/gộp theo đúng kỳ vọng.
        assertTrue(hasPermission(authorities, menuCode, PermissionType.VIEW));
        assertTrue(hasPermission(authorities, menuCode, PermissionType.EXPORT));
    }

    @Test
    @DisplayName("Stale role hoặc role không tồn tại: không có permission hợp lệ")
    void shouldReturnEmptyAuthoritiesForStaleOrMissingRole() {
        // TC04
        // Arrange: role stale/không tồn tại trả về danh sách quyền rỗng.
        Long userId = 103L;

        when(roleMenuRepository.findAuthoritiesByUserId(userId, List.of("STALE_ROLE")))
                .thenReturn(List.of());

        // Act: lấy authorities từ service.
        Map<String, List<String>> authorities = roleMenuService.getAuthorities(userId, List.of("STALE_ROLE"));

        // Assert: map authorities phải rỗng.
        assertTrue(authorities.isEmpty());
    }

    // ----------------------
    // Nhóm test guard quyền admin
    // ----------------------
    // Các test dưới đây kiểm tra các ràng buộc quan trọng trong UserServiceImpl
    // khi thu hồi quyền SYSTEM_ADMIN.

    @Test
    @DisplayName("Guard: khong tu tuoc quyen admin cua chinh minh")
    void retrieveAdminSystemRole_shouldNotAllowRemovingOwnAdminRole() {
        // TC05
        // Arrange: user hiện tại cũng chính là user bị thu hồi và đang có SYSTEM_ADMIN.
        Long currentUserId = 11L;

        RoleDto systemAdminRole = RoleDto.builder()
                .id(99L)
                .code(Constants.RoleCode.SYSTEM_ADMIN)
                .build();

        User user = new User();
        user.setId(currentUserId);

        RoleUserDto roleUserDto = RoleUserDto.builder()
                .userId(currentUserId)
                .roleId(systemAdminRole.getId())
                .build();

        when(roleService.getRoleByCode(Constants.RoleCode.SYSTEM_ADMIN)).thenReturn(systemAdminRole);
        when(userRepository.findById(currentUserId)).thenReturn(Optional.of(user));
        when(roleUserService.findByUserIdAndRoleId(currentUserId, systemAdminRole.getId())).thenReturn(roleUserDto);

        try (MockedStatic<WebUtils> webUtilsMock = org.mockito.Mockito.mockStatic(WebUtils.class)) {
            webUtilsMock.when(WebUtils::getCurrentUserId).thenReturn(currentUserId);

            // Act + Assert: service phải chặn tự thu hồi quyền với đúng mã lỗi.
            AppException ex = assertThrows(AppException.class,
                    () -> userService.retrieveAdminSystemRole(currentUserId));

            assertEquals(UserErrorCode.CANNOT_REMOVE_OWN_SYSTEM_ADMIN_ROLE, ex.getErrorCode());
            // Guard phải chặn trước khi gọi thao tác xóa quyền.
            verify(roleUserService, never()).deleteByUserIdAndRoleIds(eq(currentUserId), anyList());
        }
    }

    @Test
    @DisplayName("Guard: khong xoa admin cuoi cung")
    void retrieveAdminSystemRole_shouldNotRemoveLastActiveAdmin() {
        // TC06
        // Arrange: actor thu hồi quyền của admin khác, nhưng sau đó hệ thống không còn admin active.
        Long actorUserId = 21L;
        Long targetUserId = 22L;

        RoleDto systemAdminRole = RoleDto.builder()
                .id(199L)
                .code(Constants.RoleCode.SYSTEM_ADMIN)
                .build();

        User targetUser = new User();
        targetUser.setId(targetUserId);

        RoleUserDto targetRoleUser = RoleUserDto.builder()
                .userId(targetUserId)
                .roleId(systemAdminRole.getId())
                .build();

        when(roleService.getRoleByCode(Constants.RoleCode.SYSTEM_ADMIN)).thenReturn(systemAdminRole);
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));
        when(roleUserService.findByUserIdAndRoleId(targetUserId, systemAdminRole.getId())).thenReturn(targetRoleUser);
        when(roleUserService.existsUserActiveByRoleId(systemAdminRole.getId())).thenReturn(false);

        try (MockedStatic<WebUtils> webUtilsMock = org.mockito.Mockito.mockStatic(WebUtils.class)) {
            webUtilsMock.when(WebUtils::getCurrentUserId).thenReturn(actorUserId);

            // Act + Assert: service phải ném lỗi LAST_SYSTEM_ADMIN_CANNOT_BE_REMOVED.
            AppException ex = assertThrows(AppException.class,
                    () -> userService.retrieveAdminSystemRole(targetUserId));

            assertEquals(UserErrorCode.LAST_SYSTEM_ADMIN_CANNOT_BE_REMOVED, ex.getErrorCode());
            // Theo implementation hiện tại: xóa trước rồi mới check điều kiện, nên delete được gọi 1 lần.
            verify(roleUserService).deleteByUserIdAndRoleIds(targetUserId, List.of(systemAdminRole.getId()));
        }
    }

    private boolean hasPermission(Map<String, List<String>> authorities, String menuCode, PermissionType action) {
        // Hàm tiện ích giúp phần assert ngắn gọn, dễ đọc trong nhóm test permission.
        return authorities.getOrDefault(menuCode, List.of()).contains(action.name());
    }
}
