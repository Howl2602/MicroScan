const reportTranslations = {
  'Unauthenticated access to a resource': 'Truy cập tài nguyên không cần xác thực',
  'Protected data returned for an invalid-token probe':
    'Dữ liệu được bảo vệ đã được trả về khi kiểm tra token không hợp lệ',
  'Protected data returned for an expired-token probe':
    'Dữ liệu được bảo vệ đã được trả về khi kiểm tra token hết hạn',
  'Potential authorization weakness': 'Khả năng có điểm yếu trong phân quyền',
  "Review the endpoint's authorization policy.":
    'Rà soát chính sách phân quyền của endpoint.',
  'Review and enforce the intended authorization policy.':
    'Rà soát và thực thi chính sách phân quyền dự kiến.',
  'Review whether this resource is intended to be public. If it is protected, enforce authentication and authorization on the server for every request.':
    'Xác nhận tài nguyên này có được phép truy cập công khai hay không. Nếu cần bảo vệ, hãy yêu cầu xác thực và phân quyền ở máy chủ cho mọi request.',
  "Verify JWT signature, issuer, audience, expiry, and required claims before authorizing access; confirm the route's intended access policy.":
    'Kiểm tra chữ ký JWT, đơn vị phát hành, đối tượng nhận, thời hạn và các claim bắt buộc trước khi cấp quyền truy cập; xác nhận chính sách truy cập dự kiến của route.',
  'Enforce JWT expiration and reject expired tokens before authorizing access.':
    'Bắt buộc kiểm tra thời hạn JWT và từ chối token hết hạn trước khi cấp quyền truy cập.',
  'The response contained resource-shaped data without a token. Confirm whether the endpoint is intended to be public before changing its behavior.':
    'Phản hồi có dữ liệu giống tài nguyên dù request không có token. Hãy xác nhận endpoint có được phép công khai trước khi thay đổi hành vi.',
  'Document whether this endpoint is public or requires authentication.':
    'Ghi rõ endpoint này được truy cập công khai hay yêu cầu xác thực.',
  'If protected, require an authenticated principal on every request.':
    'Nếu endpoint cần bảo vệ, hãy yêu cầu danh tính đã xác thực trong mọi request.',
  'Enforce resource, tenant, and role authorization in the service layer.':
    'Thực thi phân quyền theo tài nguyên, tenant và vai trò ở tầng dịch vụ.',
  'Return a denial response without resource data when access is not allowed.':
    'Trả về phản hồi từ chối và không kèm dữ liệu tài nguyên khi không được phép truy cập.',
  'Repeat the request without credentials and confirm only intended public data is returned.':
    'Gửi lại request không có thông tin xác thực và xác nhận chỉ dữ liệu được phép công khai mới được trả về.',
  'Confirm an authorized user can still access permitted data.':
    'Xác nhận người dùng được cấp quyền vẫn truy cập được dữ liệu phù hợp.',
  "Confirm the endpoint's intended access policy; public data is not a vulnerability by itself.":
    'Xác nhận chính sách truy cập dự kiến của endpoint; dữ liệu công khai tự nó không phải là lỗ hổng.',
  'Resource-shaped data was returned for an invalid-token probe. Review whether the service validates the token before returning protected data.':
    'Dữ liệu giống tài nguyên đã được trả về khi kiểm tra token không hợp lệ. Hãy rà soát việc dịch vụ xác thực token trước khi trả dữ liệu được bảo vệ.',
  'Verify token signatures using a server-configured allowlist of algorithms.':
    'Xác minh chữ ký token bằng danh sách thuật toán được cấu hình phía máy chủ.',
  'Validate issuer, audience, expiry, and required claims.':
    'Kiểm tra đơn vị phát hành, đối tượng nhận, thời hạn và các claim bắt buộc.',
  'Reject invalid credentials before loading or returning protected resources.':
    'Từ chối thông tin xác thực không hợp lệ trước khi tải hoặc trả về tài nguyên được bảo vệ.',
  'Apply authorization checks to the requested resource after authentication.':
    'Kiểm tra quyền đối với tài nguyên được yêu cầu sau khi xác thực.',
  'Confirm missing, malformed, and invalid-signature tokens are denied.':
    'Xác nhận token bị thiếu, sai định dạng hoặc có chữ ký không hợp lệ đều bị từ chối.',
  'Confirm a valid authorized token can access permitted data.':
    'Xác nhận token hợp lệ và được cấp quyền có thể truy cập dữ liệu phù hợp.',
  "Use the endpoint's intended authentication policy to interpret the observed response.":
    'Dựa trên chính sách xác thực dự kiến của endpoint để đánh giá phản hồi quan sát được.',
  'If an expired-token probe is supported, the service must reject expired credentials before returning protected data.':
    'Nếu có kiểm tra token hết hạn, dịch vụ phải từ chối thông tin xác thực hết hạn trước khi trả dữ liệu được bảo vệ.',
  'Validate the token expiration claim on every authenticated request.':
    'Kiểm tra claim thời hạn token trong mọi request đã xác thực.',
  'Reject expired tokens and require the documented re-authentication flow.':
    'Từ chối token hết hạn và yêu cầu thực hiện quy trình xác thực lại đã được quy định.',
  'Keep token refresh handling separate from resource authorization.':
    'Tách riêng việc làm mới token khỏi quy trình phân quyền tài nguyên.',
  'Confirm an expired token is denied and does not return protected data.':
    'Xác nhận token hết hạn bị từ chối và không trả dữ liệu được bảo vệ.',
  'Confirm a valid, unexpired token retains its intended access.':
    'Xác nhận token hợp lệ, chưa hết hạn vẫn có quyền truy cập như dự kiến.',
  'Expired-token probing is not currently implemented by MicroScan.':
    'MicroScan hiện chưa triển khai kiểm tra token hết hạn.',
  'An authenticated request returned data for an identifier outside the captured collection baseline; verify object-level authorization.':
    'Request đã xác thực trả về dữ liệu của mã định danh nằm ngoài dữ liệu nền đã thu thập; hãy kiểm tra phân quyền ở cấp đối tượng.',
  'Derive the caller identity from the authenticated server-side principal.':
    'Lấy danh tính người gọi từ principal đã xác thực ở phía máy chủ.',
  'Constrain resource lookups by owner, tenant, or an explicit access policy.':
    'Giới hạn truy vấn tài nguyên theo chủ sở hữu, tenant hoặc chính sách truy cập cụ thể.',
  'Deny access when the caller lacks permission; do not rely on unguessable IDs.':
    'Từ chối truy cập khi người gọi không có quyền; không dựa vào mã định danh khó đoán.',
  'Apply the authorization check consistently to every operation on the object.':
    'Áp dụng kiểm tra phân quyền nhất quán cho mọi thao tác trên đối tượng.',
  "With two test accounts, confirm account A cannot read account B's object.":
    'Dùng hai tài khoản kiểm thử để xác nhận tài khoản A không thể đọc đối tượng của tài khoản B.',
  'Confirm each account can still access objects it is authorized to use.':
    'Xác nhận mỗi tài khoản vẫn truy cập được các đối tượng mà tài khoản đó được phép sử dụng.',
  'An out-of-baseline response alone does not establish ownership or intended access policy.':
    'Chỉ riêng phản hồi khác dữ liệu nền chưa đủ để xác định quyền sở hữu hoặc chính sách truy cập dự kiến.',
  'No throttling response was observed in the tested request window; review whether this endpoint needs a server-side rate-limit policy.':
    'Không quan sát thấy phản hồi giới hạn tốc độ trong khoảng request đã kiểm tra; hãy đánh giá endpoint có cần chính sách rate limit ở phía máy chủ hay không.',
  'Define limits appropriate to endpoint cost and caller identity.':
    'Xác định giới hạn phù hợp với chi phí xử lý của endpoint và danh tính người gọi.',
  'Enforce limits server-side, considering account, IP, and relevant resource keys.':
    'Thực thi giới hạn ở phía máy chủ, xét theo tài khoản, IP và các khóa tài nguyên liên quan.',
  'Return HTTP 429 and a suitable Retry-After value when the limit is exceeded.':
    'Trả về HTTP 429 cùng giá trị Retry-After phù hợp khi vượt giới hạn.',
  'Ensure proxy configuration does not let callers spoof their source identity.':
    'Đảm bảo cấu hình proxy không cho phép người gọi giả mạo danh tính nguồn.',
  'Repeat a controlled burst below and above the configured limit.':
    'Thực hiện lại một đợt request có kiểm soát ở cả dưới và trên giới hạn đã cấu hình.',
  'Confirm excess requests are throttled and normal traffic recovers as expected.':
    'Xác nhận request vượt giới hạn bị điều tiết và lưu lượng bình thường phục hồi như dự kiến.',
  'A bounded burst cannot establish the absence of limits at other thresholds or time windows.':
    'Một đợt request có giới hạn không thể xác nhận rằng không có giới hạn ở ngưỡng hoặc khoảng thời gian khác.',
  'Direct service access produced structured data while the Gateway response differed; verify that intended Gateway controls cannot be bypassed.':
    'Truy cập trực tiếp dịch vụ trả về dữ liệu có cấu trúc khác với phản hồi từ Gateway; hãy xác minh các biện pháp kiểm soát dự kiến của Gateway không thể bị vượt qua.',
  'Restrict network access so only approved Gateway components can reach backend services.':
    'Giới hạn truy cập mạng để chỉ các thành phần Gateway được phê duyệt mới có thể kết nối dịch vụ backend.',
  'Enforce authentication and authorization at the service as well as the Gateway.':
    'Thực thi xác thực và phân quyền ở cả dịch vụ lẫn Gateway.',
  'Review service bindings, firewall rules, and deployment exposure.':
    'Rà soát cấu hình binding dịch vụ, quy tắc tường lửa và phạm vi phơi lộ khi triển khai.',
  'Avoid relying on Gateway-only controls for sensitive operations.':
    'Không chỉ dựa vào kiểm soát tại Gateway đối với các thao tác nhạy cảm.',
  'Confirm direct unauthenticated access to the service is blocked or equivalently protected.':
    'Xác nhận truy cập trực tiếp không xác thực đến dịch vụ bị chặn hoặc được bảo vệ tương đương.',
  'Confirm intended requests through the Gateway continue to work.':
    'Xác nhận các request hợp lệ qua Gateway vẫn hoạt động.',
  'Review the compared evidence and intended architecture before treating a potential result as confirmed.':
    'Rà soát bằng chứng so sánh và kiến trúc dự kiến trước khi xác nhận kết quả tiềm ẩn.',
  "Review the endpoint's intended authentication and authorization policy.":
    'Rà soát chính sách xác thực và phân quyền dự kiến của endpoint.',
  'Confirm the expected access policy with the service owner.':
    'Xác nhận chính sách truy cập mong muốn với chủ sở hữu dịch vụ.',
  'Enforce authentication and resource-level authorization on the server where required.':
    'Thực thi xác thực và phân quyền ở cấp tài nguyên trên máy chủ khi cần.',
  'Repeat the same request condition after the change.':
    'Lặp lại cùng điều kiện request sau khi thay đổi.',
  'Confirm both permitted and denied access cases behave as intended.':
    'Xác nhận cả trường hợp được phép và bị từ chối đều hoạt động đúng dự kiến.',
  'This guidance is generic because no specific remediation template matches this test case.':
    'Hướng dẫn này mang tính tổng quát vì chưa có mẫu khắc phục cụ thể cho trường hợp kiểm tra này.',
  'Offline, rule-based guidance. Suggested priority is triage assistance, not a severity assessment; validate recommendations against the application.':
    'Hướng dẫn ngoại tuyến dựa trên luật. Mức ưu tiên chỉ hỗ trợ phân loại, không phải đánh giá mức độ nghiêm trọng; hãy đối chiếu khuyến nghị với ứng dụng.',
  'Offline, rule-based guidance; validate before applying.':
    'Hướng dẫn ngoại tuyến dựa trên luật; hãy kiểm tra trước khi áp dụng.',
}

const priorityTranslations = {
  high: 'cao',
  medium: 'trung bình',
  review: 'cần rà soát',
}

export function localizeReportText(value) {
  return typeof value === 'string' ? reportTranslations[value] ?? value : value
}

export function localizeReportPriority(value) {
  return priorityTranslations[value] ?? value ?? 'cần rà soát'
}

export function localizeReportFinding(finding) {
  if (!finding || typeof finding !== 'object') return finding
  const remediation = finding.remediation
  return {
    ...finding,
    name: localizeReportText(finding.name),
    recommendation: localizeReportText(finding.recommendation),
    ...(remediation && typeof remediation === 'object'
      ? {
          remediation: {
            ...remediation,
            root_cause: localizeReportText(remediation.root_cause),
            actions: Array.isArray(remediation.actions)
              ? remediation.actions.map(localizeReportText)
              : remediation.actions,
            retest_steps: Array.isArray(remediation.retest_steps)
              ? remediation.retest_steps.map(localizeReportText)
              : remediation.retest_steps,
            suggested_priority: localizeReportPriority(remediation.suggested_priority),
            limitation: localizeReportText(remediation.limitation),
            note: localizeReportText(remediation.note),
          },
        }
      : {}),
  }
}
