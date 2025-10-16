<?php declare(strict_types=1);

namespace Coercive\Security\Xss;

use PHPUnit\Framework\TestCase;

final class XssUrlTest extends TestCase
{
	private XssUrl $xss;

	protected function setUp(): void
	{
		$this->xss = new XssUrl;
	}

	public function testIsXss(): void
	{
		// URL normale
		$this->assertFalse($this->xss->setUrl('https://example.com')->isXss());
		$this->assertFalse($this->xss->setUrl('https://example.com/page?id=42')->isXss());
		$this->assertFalse($this->xss->setUrl('http://aouka.com/search?q=test')->isXss());

		// XSS évidente : script HTML
		$this->assertTrue($this->xss->setUrl('<script>alert(1)</script>')->isXss());
		$this->assertTrue($this->xss->setUrl('https://example.com/<script>alert(1)</script>')->isXss());

		// javascript: pseudo-protocoles
		$this->assertTrue($this->xss->setUrl('javascript:alert(1)')->isXss());
		$this->assertTrue($this->xss->setUrl('JaVaScRiPt:alert("x")')->isXss());
		$this->assertTrue($this->xss->setUrl('vbscript:msgbox("x")')->isXss());

		// data URI malicieuse
		$this->assertTrue($this->xss->setUrl('data:text/html,<script>alert(1)</script>')->isXss());
		$this->assertTrue($this->xss->setUrl('data:text/javascript,alert(1)')->isXss());

		// URL avec attributs injectés
		$this->assertTrue($this->xss->setUrl('https://example.com?q=<img src=x onerror=alert(1)>')->isXss());
		$this->assertTrue($this->xss->setUrl('https://test.com?q="><svg onload=alert(1)>')->isXss());

		// URL obfusquée
		$this->assertTrue($this->xss->setUrl('JaVaScRiPt:%61%6C%65%72%74(1)')->isXss());
		$this->assertTrue($this->xss->setUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==')->isXss());

		// Query string bénigne
		$this->assertFalse($this->xss->setUrl('https://example.com/page?q=hello+world')->isXss());
		$this->assertTrue($this->xss->setUrl('https://example.com?q=<b>bold</b>')->isXss());

		// Cas extrêmes
		$this->assertFalse($this->xss->setUrl('mailto:test@example.com')->isXss());
		$this->assertFalse($this->xss->setUrl('ftp://ftp.example.com/file.txt')->isXss());
		$this->assertTrue($this->xss->setUrl('javascript://comment%0Aalert(1)')->isXss());

		// Vide
		$this->assertFalse($this->xss->setUrl('')->isXss());
	}

	public function testIsXssWithRealisticUrls(): void
	{
		// 1) Image tag injection inside a query param (classic)
		$this->assertTrue($this->xss->setUrl('https://example.com/?q=<img src=x onerror=alert(1)>')->isXss());

		// 2) SVG payload in param (onload/onmouseover)
		$this->assertTrue($this->xss->setUrl('https://app.example.com/search?q=%3Csvg%20onload%3Dalert(1)%3E%3C%2Fsvg%3E')->isXss());

		// 3) HTML-encoded then URL-encoded payload (double encoding common in filters)
		$this->assertTrue($this->xss->setUrl('https://site.test/?payload=%253Cscript%253Ealert(1)%253C%252Fscript%253E')->isXss());

		// 4) data URI with HTML containing script (embedded page)
		$this->assertTrue($this->xss->setUrl('https://example.com/?redirect=data:text/html,%3Cscript%3Ealert(1)%3C/script%3E')->isXss());

		// 5) data URI base64 with script (base64-encoded HTML)
		$this->assertTrue($this->xss->setUrl('https://example.com/?d=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==')->isXss());

		// 6) SVG payload URL inside an img src param with mixed-case percent-encoding
		$this->assertTrue($this->xss->setUrl('https://cdn.example.com/?img=%3Cimg%20src%3Dx%20onerror%3D%61%6C%65%72%74%28%31%29%3E')->isXss());

		// 7) href injection (link text includes encoded javascript:) — typical phishing / XSS vector when inserted into href attribute later
		$this->assertTrue($this->xss->setUrl('https://site/?link=%6a%61%76%61%73%63%72%69%70%74:alert(1)')->isXss());

		// 8) srcdoc usage: page embeds remote srcdoc param that contains HTML/JS
		$this->assertTrue($this->xss->setUrl('https://service/?srcdoc=%3Ciframe%20srcdoc%3D%22%3Cscript%3Ealert(1)%3C%2Fscript%3E%22%3E')->isXss());

		// 9) onerror inside encoded image tag and nested in JSON param
		$this->assertTrue($this->xss->setUrl('https://api/?data=%7B%22html%22%3A%22%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E%22%7D')->isXss());

		// 10) double-encoded SVG/JS inside param (very common to bypass naive filters)
		$this->assertTrue($this->xss->setUrl('https://example/?p=%25253Csvg%252520onload%253Dalert(1)%25253E')->isXss());

		// 11) obfuscated with mixed case and percent encodings for "javascript:"
		$this->assertTrue($this->xss->setUrl('https://example.com/?u=JaVaScRiPt%3A%61%6C%65%72%74%28%31%29')->isXss());

		// 12) valid-looking image URL but with srcset containing a JavaScript pseudo-protocol in param
		$this->assertTrue($this->xss->setUrl('https://images.example.com/pic.jpg?srcset=1x,javascript:alert(1) 2x')->isXss());

		// 13) attribute-breaking injection: closing quote + onmouseover
		$this->assertTrue($this->xss->setUrl('https://example.com/?title=%22%3E%3Cdiv%20onmouseover%3Dalert(1)%3E')->isXss());

		// 14) iframe src pointing to javascript: inside a param (realistic when apps accept raw HTML fragments)
		$this->assertTrue($this->xss->setUrl('https://cms/?fragment=%3Ciframe%20src%3D%22javascript:alert(1)%22%3E')->isXss());

		// 15) mailto with body containing encoded script (should be flagged because content may later be rendered)
		$this->assertTrue($this->xss->setUrl('https://webmail.example/compose?to=test@ex.com&body=%3Cscript%3Ealert(1)%3C%2Fscript%3E')->isXss());

		// 16) benign: query param contains "<b>bold</b>" (allowed HTML markup but no event handlers or scripts)
		$this->assertTrue($this->xss->setUrl('https://example.com/?q=%3Cb%3Ebold%3C%2Fb%3E')->isXss());

		// 17) benign: 'javascript' appears in path but not as scheme (domain/path segment) → should NOT be flagged
		$this->assertFalse($this->xss->setUrl('https://example.com/static/js/javascript-library.js')->isXss());

		// 18) benign: data URI of plain text (text/plain) — allowed in many contexts; still we assume harmless (false)
		$this->assertFalse($this->xss->setUrl('https://example.com/?d=data:text/plain,Hello%20World')->isXss());

		// 19) trick: percent-encoded angle brackets but used purely as text (should be flagged conservatively in many detectors — we flag true)
		$this->assertTrue($this->xss->setUrl('https://example.com/?note=%3Cscript%3E%26lt%3B%2Fscript%3E')->isXss());

		// 20) tricky: unicode homoglyphs used to mask "script" (e.g., Cyrillic 'с' vs Latin 'c'); detector should be robust → flag true
		// Note: actual homoglyph examples may vary; here is a plausible scenario where someone mixes Cyrillic letters
		$this->assertTrue($this->xss->setUrl('https://example.com/?q=%D0%BD%D0%B0%D0%B2%D1%96%3C%F1%F1%F1%3E')->isXss());

		// 22) obfuscated using HTML entities inside param (e.g. &lt;img onerror=... &gt;)
		$this->assertTrue($this->xss->setUrl('https://example.com/?p=&lt;img%20src=x%20onerror=alert(1)&gt;')->isXss());

		// 23) false positive check: ftp link with "data" in filename — should be benign
		$this->assertFalse($this->xss->setUrl('ftp://files.example.com/data/text.txt')->isXss());

		// 24) empty string (no URL) → not XSS
		$this->assertFalse($this->xss->setUrl('')->isXss());
	}

	public function testFiltered(): void
	{
		$this->assertSame('https://example.com/?q=img src=x onerror=alert1', $this->xss->setUrl('https://example.com/?q=<img src=x onerror=alert(1)>')->getFiltered());

		$this->assertSame('https://app.example.com/search?q=svg%20onload%3Dalert1%2Fsvg', $this->xss->setUrl('https://app.example.com/search?q=%3Csvg%20onload%3Dalert(1)%3E%3C%2Fsvg%3E')->getFiltered());

		$this->assertSame('https://site.test/?payload=3Cscript3Ealert13C2Fscript3E', $this->xss->setUrl('https://site.test/?payload=%253Cscript%253Ealert(1)%253C%252Fscript%253E')->getFiltered());

		$this->assertSame('https://example.com/?redirect=data:text/html,scriptalert1/script', $this->xss->setUrl('https://example.com/?redirect=data:text/html,%3Cscript%3Ealert(1)%3C/script%3E')->getFiltered());

		$this->assertSame('https://example.com/?d=data:text/htmlbase64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', $this->xss->setUrl('https://example.com/?d=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==')->getFiltered());

		$this->assertSame('https://cdn.example.com/?img=img%20src%3Dx%20onerror%3D%61%6C%65%72%74%31', $this->xss->setUrl('https://cdn.example.com/?img=%3Cimg%20src%3Dx%20onerror%3D%61%6C%65%72%74%28%31%29%3E')->getFiltered());

		$this->assertSame('https://site/?link=%6a%61%76%61%73%63%72%69%70%74:alert1', $this->xss->setUrl('https://site/?link=%6a%61%76%61%73%63%72%69%70%74:alert(1)')->getFiltered());

		$this->assertSame('https://service/?srcdoc=iframe%20srcdoc%3Dscriptalert1%2Fscript', $this->xss->setUrl('https://service/?srcdoc=%3Ciframe%20srcdoc%3D%22%3Cscript%3Ealert(1)%3C%2Fscript%3E%22%3E')->getFiltered());

		$this->assertSame('https://api/?data=%7Bhtml%3Aimg%20src%3Dx%20onerror%3Dalert1%7D', $this->xss->setUrl('https://api/?data=%7B%22html%22%3A%22%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E%22%7D')->getFiltered());

		$this->assertSame('https://example/?p=253Csvg2520onload3Dalert1253E', $this->xss->setUrl('https://example/?p=%25253Csvg%252520onload%253Dalert(1)%25253E')->getFiltered());

		$this->assertSame('https://example.com/?u=JaVaScRiPt%3A%61%6C%65%72%74%31', $this->xss->setUrl('https://example.com/?u=JaVaScRiPt%3A%61%6C%65%72%74%28%31%29')->getFiltered());

		$this->assertSame('https://images.example.com/pic.jpg?srcset=1x,javascript:alert1 2x', $this->xss->setUrl('https://images.example.com/pic.jpg?srcset=1x,javascript:alert(1) 2x')->getFiltered());

		$this->assertSame('https://example.com/?title=div%20onmouseover%3Dalert1', $this->xss->setUrl('https://example.com/?title=%22%3E%3Cdiv%20onmouseover%3Dalert(1)%3E')->getFiltered());

		$this->assertSame('https://cms/?fragment=iframe%20src%3Djavascript:alert1', $this->xss->setUrl('https://cms/?fragment=%3Ciframe%20src%3D%22javascript:alert(1)%22%3E')->getFiltered());

		$this->assertSame('https://webmail.example/compose?to=test@ex.com&body=scriptalert1%2Fscript', $this->xss->setUrl('https://webmail.example/compose?to=test@ex.com&body=%3Cscript%3Ealert(1)%3C%2Fscript%3E')->getFiltered());

		$this->assertSame('https://example.com/?q=bbold%2Fb', $this->xss->setUrl('https://example.com/?q=%3Cb%3Ebold%3C%2Fb%3E')->getFiltered());

		$this->assertSame('https://example.com/static/js/javascript-library.js', $this->xss->setUrl('https://example.com/static/js/javascript-library.js')->getFiltered());

		$this->assertSame('https://example.com/?d=data:text/plain,Hello%20World', $this->xss->setUrl('https://example.com/?d=data:text/plain,Hello%20World')->getFiltered());

		$this->assertSame('https://example.com/?note=script%26lt%3B%2Fscript', $this->xss->setUrl('https://example.com/?note=%3Cscript%3E%26lt%3B%2Fscript%3E')->getFiltered());

		$this->assertSame('https://example.com/?q=%D0%BD%D0%B0%D0%B2%D1%96%F1%F1%F1', $this->xss->setUrl('https://example.com/?q=%D0%BD%D0%B0%D0%B2%D1%96%3C%F1%F1%F1%3E')->getFiltered());

		$this->assertSame('https://example.com/?p=img%20src=x%20onerror=alert1', $this->xss->setUrl('https://example.com/?p=&lt;img%20src=x%20onerror=alert(1)&gt;')->getFiltered());

		$this->assertSame('ftp://files.example.com/data/text.txt', $this->xss->setUrl('ftp://files.example.com/data/text.txt')->getFiltered());

		$this->assertSame('', $this->xss->setUrl('')->getFiltered());
	}
}