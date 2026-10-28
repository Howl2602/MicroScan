import { Box, Card, CardContent, Chip, Link, Typography } from '@mui/material'

const sections = [
  ['api-security', 'API Security'],
  ['authentication-jwt', 'Broken Authentication / JWT'],
  ['bola', 'BOLA'],
  ['rate-limiting', 'Rate Limiting'],
  ['gateway-bypass', 'Gateway Bypass'],
  ['reading-results', 'How to Read Results'],
  ['glossary', 'Glossary'],
  ['references', 'References'],
]

const glossaryGroups = [
  {
    title: 'API and architecture',
    terms: [
      ['API', 'Giao diện lập trình ứng dụng', 'Quy tắc để các phần mềm trao đổi dữ liệu và yêu cầu.', 'Ứng dụng gọi API để lấy danh sách đơn hàng.'],
      ['Endpoint', 'Điểm cuối API', 'Địa chỉ và phương thức mà client dùng để gọi một chức năng.', 'GET /api/orders là ví dụ minh họa.'],
      ['HTTP Method', 'Phương thức HTTP', 'Cho biết loại thao tác của request, như GET, POST, PUT hoặc DELETE.', 'GET thường dùng để đọc dữ liệu.'],
      ['Request', 'Yêu cầu', 'Thông điệp client gửi đến server.'],
      ['Response', 'Phản hồi', 'Thông điệp server gửi lại sau khi xử lý request.'],
      ['Header', 'Phần đầu', 'Metadata đi kèm request hoặc response, thường chứa kiểu nội dung hay thông tin xác thực.'],
      ['Body', 'Phần thân', 'Nội dung dữ liệu của request hoặc response.'],
      ['Status Code', 'Mã trạng thái', 'Mã HTTP mô tả kết quả xử lý, chẳng hạn 200, 401, 403 hoặc 429.'],
      ['Microservice', 'Vi dịch vụ', 'Dịch vụ nhỏ đảm nhiệm một phần chức năng và giao tiếp với dịch vụ khác qua API.'],
      ['API Gateway', 'Cổng API', 'Thành phần nhận và định tuyến request; thường áp dụng xác thực, chính sách và kiểm soát truy cập.'],
      ['Backend Service', 'Dịch vụ backend', 'Dịch vụ phía máy chủ thực hiện xử lý nghiệp vụ và truy cập dữ liệu.'],
      ['OpenAPI', 'Đặc tả OpenAPI', 'Định dạng mô tả các đường dẫn, phương thức và schema của API.'],
    ],
  },
  {
    title: 'Identity and access',
    terms: [
      ['Authentication', 'Xác thực', 'Kiểm tra danh tính của người dùng hoặc dịch vụ.'],
      ['Authorization', 'Phân quyền', 'Kiểm tra danh tính đã xác thực có được phép thực hiện hành động cụ thể hay không.'],
      ['Access Control', 'Kiểm soát truy cập', 'Các quy tắc quyết định ai được truy cập tài nguyên nào và trong điều kiện nào.'],
      ['Ownership', 'Quyền sở hữu', 'Mối liên hệ giữa người dùng và đối tượng dữ liệu; backend phải kiểm tra quyền với từng đối tượng.'],
      ['Protected Resource', 'Tài nguyên được bảo vệ', 'Dữ liệu hoặc chức năng chỉ người gọi có quyền phù hợp mới được truy cập.'],
      ['JWT', 'JSON Web Token', 'Token có các phần Header, Payload và Signature; payload thường chỉ được mã hóa dạng Base64URL, không mặc định được mã hóa bảo mật.'],
      ['Claim', 'Mệnh đề trong token', 'Trường thông tin trong JWT, ví dụ exp (hạn dùng), iss (bên phát hành) hoặc aud (đối tượng nhận).'],
      ['Signature', 'Chữ ký', 'Giá trị mật mã giúp kiểm tra token không bị sửa đổi và được phát hành hợp lệ.'],
      ['Access Token', 'Token truy cập', 'Thông tin xác thực ngắn hạn thường được gửi khi gọi API được bảo vệ.'],
      ['Refresh Token', 'Token làm mới', 'Thông tin xác thực dùng để xin access token mới; cần được bảo vệ chặt chẽ.'],
      ['Expiration (exp)', 'Thời điểm hết hạn', 'Claim quy định thời điểm token không còn được chấp nhận.'],
    ],
  },
  {
    title: 'Vulnerability and request controls',
    terms: [
      ['BOLA', 'Lỗi phân quyền cấp đối tượng', 'Người dùng đã xác thực truy cập được một đối tượng không thuộc quyền của mình.'],
      ['IDOR', 'Tham chiếu đối tượng trực tiếp không an toàn', 'Lỗi truy cập đối tượng qua một mã tham chiếu mà server không kiểm tra quyền phù hợp; thường liên quan BOLA.'],
      ['Broken Authentication', 'Xác thực bị lỗi', 'Lỗi trong xác minh danh tính hoặc vòng đời thông tin xác thực có thể cho phép truy cập trái phép.'],
      ['Rate Limit', 'Giới hạn tần suất', 'Số request tối đa được phép trong một khoảng thời gian nhất định.'],
      ['Throttling', 'Điều tiết lưu lượng', 'Giảm tốc độ hoặc từ chối request khi vượt chính sách sử dụng.'],
      ['HTTP 429', 'Quá nhiều yêu cầu', 'Mã trạng thái server thường dùng khi client gửi request vượt giới hạn.'],
      ['Retry-After', 'Thời gian chờ trước khi thử lại', 'Header có thể cho biết khi nào client nên gửi request tiếp theo.'],
      ['Route Discovery', 'Khám phá route', 'Quá trình tìm các đường dẫn API tiềm năng trong nguồn hoặc phản hồi được phép kiểm tra.'],
      ['Endpoint Inventory', 'Danh mục endpoint', 'Tập hợp các endpoint được ghi nhận trong phạm vi khám phá; không đồng nghĩa tất cả đã được kiểm thử.'],
      ['Scan Profile', 'Chế độ cấu hình scan', 'Tập hợp lựa chọn và phạm vi kiểm thử được áp dụng cho lần scan.'],
      ['Standard Scan', 'Scan tiêu chuẩn', 'Chế độ scan có phạm vi kiểm thử được giới hạn theo lựa chọn của công cụ.'],
      ['Full Scan', 'Scan đầy đủ', 'Chế độ scan mở rộng hơn theo cấu hình hiện tại; tên chế độ không đảm bảo mọi endpoint đều được thử.'],
    ],
  },
  {
    title: 'Findings and coverage',
    terms: [
      ['Finding', 'Phát hiện', 'Kết quả của phép thử có bằng chứng về vấn đề bảo mật; hãy đọc trạng thái và bằng chứng kèm theo.'],
      ['Evidence', 'Bằng chứng', 'Request, response hoặc dữ liệu quan sát hỗ trợ kết luận của một phép thử.'],
      ['Severity', 'Mức độ nghiêm trọng', 'Mức độ tác động tiềm tàng nếu vấn đề được khai thác. Severity không phải độ chắc chắn của kết luận.'],
      ['Confidence', 'Độ tin cậy', 'Mức độ bằng chứng hỗ trợ kết luận; không phải mức độ tác động.'],
      ['False Positive', 'Dương tính giả', 'Kết quả bị báo là vấn đề nhưng xác minh thêm cho thấy không có lỗ hổng tương ứng.'],
      ['False Negative', 'Âm tính giả', 'Lỗ hổng tồn tại nhưng phép thử không phát hiện được.'],
      ['Inconclusive', 'Chưa thể kết luận', 'Bằng chứng chưa đủ để xác nhận hoặc bác bỏ vấn đề.'],
      ['Skipped', 'Bị bỏ qua', 'Phép thử tương ứng chưa được thực hiện; điều này không có nghĩa endpoint an toàn.'],
      ['In-scope', 'Trong phạm vi', 'Mục tiêu được cho phép và cấu hình để kiểm thử.'],
      ['Out-of-scope', 'Ngoài phạm vi', 'Mục tiêu không được phép hoặc không được cấu hình để kiểm thử.'],
      ['Discovered', 'Được phát hiện', 'Endpoint được ghi nhận qua discovery; chưa nói liệu endpoint có thể được kiểm thử hay không.'],
      ['Eligible', 'Đủ điều kiện', 'Endpoint phù hợp với tiêu chí và phạm vi của một loại phép thử.'],
      ['Selected', 'Được chọn', 'Endpoint được đưa vào lựa chọn thực thi; chưa khẳng định request kiểm thử đã chạy.'],
      ['Tested', 'Đã kiểm thử', 'Có phép thử đã thực sự được thực hiện; xem trạng thái từng test case để hiểu độ bao phủ.'],
    ],
  },
]

const referenceLinks = [
  {
    href: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/',
    label: 'OWASP API Security Top 10 2023',
    note: 'Tham khảo các nhóm rủi ro API, bao gồm Broken Authentication (API2) và Unrestricted Resource Consumption (API4).',
  },
  {
    href: 'https://owasp.org/www-project-api-security/',
    label: 'OWASP API Security Project',
    note: 'Tổng quan dự án và tài liệu bảo mật API của OWASP.',
  },
  {
    href: 'https://learn.microsoft.com/en-us/azure/api-management/mitigate-owasp-api-threats',
    label: 'Microsoft Learn - Mitigate OWASP API security threats',
    note: 'Hướng dẫn giảm thiểu các mối đe dọa bảo mật API.',
  },
]

function SectionCard({ id, title, children }) {
  return (
    <Card component="section" id={id} sx={{ mb: 2, scrollMarginTop: 24 }}>
      <CardContent sx={{ p: { xs: 2, sm: 3 }, '&:last-child': { pb: { xs: 2, sm: 3 } } }}>
        <Typography variant="h5" component="h2" sx={{ mb: 2, fontWeight: 700 }}>
          {title}
        </Typography>
        {children}
      </CardContent>
    </Card>
  )
}

function BulletList({ items }) {
  return (
    <Box component="ul" sx={{ listStyle: 'none', p: 0, m: 0 }}>
      {items.map((item) => (
        <Box
          component="li"
          key={item}
          sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, mb: 1, color: 'text.primary' }}
        >
          <Box component="span" aria-hidden="true" sx={{ flexShrink: 0 }}>
            -
          </Box>
          <Box component="span" sx={{ color: 'text.primary' }}>
            {item}
          </Box>
        </Box>
      ))}
    </Box>
  )
}

export default function IntroductionPage() {
  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', pb: 4 }}>
      <Box sx={{ mb: 3 }}>
        <Chip label="MICROSCAN GUIDE" color="primary" variant="outlined" size="small" sx={{ mb: 1.5 }} />
        <Typography variant="h4" component="h1" sx={{ fontWeight: 700, mb: 1 }}>
          Introduction
        </Typography>
        <Typography color="text.secondary">
          Hướng dẫn đọc các khái niệm bảo mật API, phạm vi kiểm thử và bằng chứng trong báo cáo MicroScan.
          Đây là tài liệu tham khảo trong ứng dụng, không phải kết quả kiểm thử mục tiêu.
        </Typography>
      </Box>

      <Card component="nav" aria-label="Mục lục Introduction" sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5 }}>Mục lục</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {sections.map(([id, title]) => (
              <Link key={id} href={`#${id}`} underline="hover" sx={{ px: 1.25, py: 0.75, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                {title}
              </Link>
            ))}
          </Box>
        </CardContent>
      </Card>

      <SectionCard id="api-security" title="A. Tổng quan về API Security">
        <Typography color="text.secondary" sx={{ mb: 1.5 }}>
          API (Application Programming Interface) là giao diện để ứng dụng trao đổi dữ liệu và yêu cầu.
          Trong kiến trúc microservices, các dịch vụ thường gọi API của nhau để phối hợp một luồng nghiệp vụ.
          API cần xác thực danh tính, phân quyền cho từng hành động và giới hạn tài nguyên để giảm nguy cơ
          truy cập trái phép, lạm dụng hoặc làm suy giảm dịch vụ.
        </Typography>
        <BulletList items={[
          'Authentication (xác thực): kiểm tra bạn là ai, ví dụ xác minh thông tin đăng nhập hoặc token.',
          'Authorization (phân quyền): kiểm tra bạn có quyền thực hiện hành động này trên tài nguyên cụ thể hay không.',
          'Xác thực thành công không tự động đồng nghĩa với được phép đọc mọi dữ liệu; backend cần kiểm tra quyền tại mỗi lần truy cập.',
        ]} />
      </SectionCard>

      <SectionCard id="authentication-jwt" title="B. Broken Authentication / JWT">
        <Typography color="text.secondary" sx={{ mb: 1.5 }}>
          Broken Authentication là lỗi triển khai xác minh danh tính hoặc quản lý thông tin xác thực.
          Hậu quả có thể là truy cập trái phép hoặc chiếm dụng phiên. JWT (JSON Web Token) thường gồm
          Header (kiểu token/thuật toán), Payload (các claim) và Signature (chữ ký xác minh tính toàn vẹn).
          JWT không mặc định được mã hóa; payload thường có thể đọc được, nên không đặt bí mật vào đó.
        </Typography>
        <BulletList items={[
          'Access token dùng để gọi API; refresh token có thể dùng để xin token mới và cần được bảo vệ.',
          'exp quy định thời điểm hết hạn; iss xác định bên phát hành; aud xác định đối tượng nhận dự kiến.',
          'Các tình huống cần xem xét: token hết hạn vẫn được chấp nhận; chữ ký không được xác minh; thuật toán hoặc cấu hình xác minh sai; endpoint được cho là bảo vệ vẫn truy cập được khi thiếu token hoặc dùng token không hợp lệ.',
          'Phòng ngừa: xác minh chữ ký và claim cần thiết, kiểm tra thời hạn, cấu hình thuật toán được phép một cách rõ ràng, và bảo vệ thông tin đăng nhập/token.',
          'Một HTTP 200 đơn lẻ không đủ chứng minh lỗ hổng. Cần xem response, nội dung, trạng thái xác thực, đối chứng và bằng chứng cụ thể; lỗi cấu hình JWT khác nhau cũng không nên gộp thành một loại.',
        ]} />
        <Typography color="text.secondary" variant="body2" sx={{ mt: 2 }}>
          Tham khảo: <Link href={referenceLinks[0].href} target="_blank" rel="noreferrer">OWASP API Security Top 10 2023 - API2 Broken Authentication</Link>.
        </Typography>
      </SectionCard>

      <SectionCard id="bola" title="C. BOLA - Broken Object Level Authorization">
        <Typography color="text.secondary" sx={{ mb: 1.5 }}>
          BOLA xảy ra khi người dùng đã xác thực có thể truy cập một đối tượng mà họ không có quyền.
          Nếu backend chỉ kiểm tra danh tính mà không kiểm tra quyền trên đối tượng được yêu cầu,
          việc thay đổi ID trong request có thể làm lộ hoặc cho phép sửa dữ liệu của người khác.
        </Typography>
        <Box component="pre" sx={{ p: 2, overflowX: 'auto', bgcolor: 'background.default', border: '1px solid', borderColor: 'divider', borderRadius: 1, color: 'primary.main' }}>
          {'GET /api/orders/1\nGET /api/orders/2'}
        </Box>
        <Typography color="text.secondary" sx={{ mt: 1.5 }}>
          Đây chỉ là ví dụ minh họa, không khẳng định các endpoint này tồn tại trong mục tiêu. Nếu người dùng
          có thể đọc đơn hàng của người khác mà không có quyền, đó có thể là BOLA. Phòng ngừa bằng cách kiểm tra
          quyền sở hữu hoặc quyền truy cập ở backend cho từng đối tượng; không dựa vào ID khó đoán để thay thế kiểm soát truy cập.
        </Typography>
        <Typography color="text.secondary" variant="body2" sx={{ mt: 2 }}>
          Tham khảo: <Link href={referenceLinks[0].href} target="_blank" rel="noreferrer">OWASP API Security Top 10 2023 - API1 Broken Object Level Authorization</Link>.
        </Typography>
      </SectionCard>

      <SectionCard id="rate-limiting" title="D. Rate Limiting / Unrestricted Resource Consumption">
        <Typography color="text.secondary" sx={{ mb: 1.5 }}>
          Rate limiting giới hạn số request trong một khoảng thời gian để bảo vệ tính sẵn sàng và tài nguyên.
          Request rate là tốc độ gửi request; rate limit là ngưỡng cho phép; throttling là điều tiết hoặc từ chối
          khi vượt ngưỡng. HTTP 429 Too Many Requests thường báo vượt giới hạn; Retry-After có thể cho biết khi nào thử lại.
        </Typography>
        <BulletList items={[
          'Thiếu giới hạn phù hợp có thể cho phép lạm dụng API, làm suy giảm hiệu năng hoặc phát sinh chi phí tài nguyên.',
          'Phòng ngừa: giới hạn theo người dùng, API key hoặc IP tùy ngữ cảnh; đặt ngưỡng riêng cho endpoint nhạy cảm; giám sát mức tiêu thụ.',
          '“Không phát hiện rate limit trong phạm vi thử nghiệm” chỉ mô tả quan sát trong phạm vi đó, không tự xác nhận lỗ hổng. Trang tài liệu này không thực hiện kiểm thử tải.',
        ]} />
        <Typography color="text.secondary" variant="body2" sx={{ mt: 2 }}>
          Tham khảo: <Link href={referenceLinks[0].href} target="_blank" rel="noreferrer">OWASP API Security Top 10 2023 - API4 Unrestricted Resource Consumption</Link>.
        </Typography>
      </SectionCard>

      <SectionCard id="gateway-bypass" title="E. Gateway Bypass">
        <Typography color="text.secondary" sx={{ mb: 1.5 }}>
          API Gateway nhận và định tuyến request, đồng thời thường áp dụng xác thực, chính sách và kiểm soát truy cập.
          Gateway bypass là tình huống có thể gửi request đến backend bằng một đường không được bảo vệ tương đương
          với đường qua gateway.
        </Typography>
        <Box component="pre" sx={{ p: 2, overflowX: 'auto', bgcolor: 'background.default', border: '1px solid', borderColor: 'divider', borderRadius: 1, color: 'primary.main' }}>
          {'Client → API Gateway → Backend Service\nClient ───────────────→ Backend Service (nếu bị phơi bày ngoài ý muốn)'}
        </Box>
        <Typography color="text.secondary" sx={{ mt: 1.5 }}>
          Nếu backend mặc định tin rằng gateway đã làm mọi kiểm tra, đường truy cập khác có thể bỏ qua chính sách dự kiến.
          Phòng ngừa bằng cách hạn chế truy cập trực tiếp đến backend, áp dụng kiểm soát phù hợp tại service và chỉ tin
          các header do thành phần đáng tin cậy thiết lập. Đây là tình huống kiến trúc cần bằng chứng; không mặc định mọi
          backend hoặc endpoint đều có thể truy cập trực tiếp. Gateway Bypass không được trình bày ở đây như một mục riêng
          của OWASP API Security Top 10 2023.
        </Typography>
      </SectionCard>

      <SectionCard id="reading-results" title="F. How to Read Results - Cách đọc kết quả MicroScan">
        <Typography color="text.secondary" sx={{ mb: 1.5 }}>
          Báo cáo MicroScan phân biệt số endpoint discovered, eligible, selected và actually tested; endpoint discovery
          cũng hiển thị verification status, còn inventory scan có thể ghi security_status là tested hoặc skipped.
        </Typography>
        <BulletList items={[
          'Discovered: được ghi nhận trong inventory; endpoint được phát hiện không đồng nghĩa endpoint có lỗ hổng.',
          'Eligible: phù hợp với tiêu chí của phép thử và phạm vi hiện tại. Eligible chưa có nghĩa đã được chọn hoặc đã gửi request.',
          'Selected: được đưa vào lựa chọn thực thi. Có thể bị giới hạn bởi lựa chọn nhóm/endpoint hoặc chính sách scan; selected không tự chứng minh request đã chạy.',
          'Tested / actually tested: báo cáo dùng bộ đếm endpoint đã thực sự được kiểm thử. Xem thêm test_cases_attempted, test_cases_completed, skipped_tests, inconclusive_tests, error_tests và trạng thái từng test case để đánh giá độ bao phủ.',
          'Finding: kết quả có trạng thái và bằng chứng riêng; báo cáo phân biệt confirmed và potential. Endpoint được phát hiện hay được chọn không tự trở thành finding.',
          'Endpoint có thể chưa được thử do ngoài phạm vi, route động chưa giải quyết được, thiếu điều kiện kiểm thử, không phù hợp tiêu chí, giới hạn lựa chọn hoặc phép thử bị bỏ qua theo chính sách an toàn.',
          'HTTP 401/403 không tự chứng minh endpoint an toàn hoặc không tồn tại. Chúng chỉ là phản hồi cần được hiểu cùng ngữ cảnh và bằng chứng.',
          'Inconclusive nghĩa là chưa đủ bằng chứng để kết luận. Skipped nghĩa là phép thử chưa được thực hiện, không phải endpoint an toàn.',
          'Kết luận scan chỉ phản ánh phép thử thực sự đã thực hiện và bằng chứng thu được. “Không phát hiện” trong tested scope không chứng minh toàn bộ hệ thống an toàn.',
        ]} />
      </SectionCard>

      <SectionCard id="glossary" title="Glossary - Thuật ngữ bảo mật">
        <Typography color="text.secondary" sx={{ mb: 2 }}>
          Các định nghĩa dưới đây giải thích thuật ngữ chung; trạng thái và phạm vi cụ thể cần được đọc theo dữ liệu của từng báo cáo.
        </Typography>
        {glossaryGroups.map((group) => (
          <Box component="details" key={group.title} sx={{ mb: 1.5 }}>
            <Box component="summary" sx={{ cursor: 'pointer', fontWeight: 700, color: 'primary.main', mb: 1 }}>
              {group.title}
            </Box>
            <Box sx={{ overflowX: 'auto' }}>
              <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', minWidth: 560, '& th, & td': { textAlign: 'left', verticalAlign: 'top', borderBottom: '1px solid', borderColor: 'divider', p: 1 } }}>
                <thead>
                  <tr><th>English term</th><th>Nghĩa tiếng Việt</th><th>Giải thích / ví dụ</th></tr>
                </thead>
                <tbody>
                  {group.terms.map(([term, translation, description, example]) => (
                    <tr key={term}>
                      <td><Typography variant="body2" sx={{ fontWeight: 700 }}>{term}</Typography></td>
                      <td><Typography variant="body2" color="text.secondary">{translation}</Typography></td>
                      <td>
                        <Typography variant="body2" color="text.secondary">{description}</Typography>
                        {example && <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{example}</Typography>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Box>
            </Box>
          </Box>
        ))}
      </SectionCard>

      <SectionCard id="references" title="Nguồn tham khảo">
        <Box component="ul" sx={{ pl: 3, mb: 0, '& li': { mb: 1.5 } }}>
          {referenceLinks.map((reference) => (
            <li key={reference.href}>
              <Link href={reference.href} target="_blank" rel="noreferrer">{reference.label}</Link>
              <Typography color="text.secondary" variant="body2">{reference.note}</Typography>
            </li>
          ))}
        </Box>
      </SectionCard>
    </Box>
  )
}
