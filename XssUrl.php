<?php
namespace Coercive\Security\Xss;

/**
 * XSS URL
 *
 * @package		Coercive\Security\Xss
 * @link		@link https://github.com/Coercive/Xss
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2017 - 2018 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class XssUrl {

    # <
    const LEFT = [
        "<",
        "&lt;",
        "%3C",
        "%25",
        "%253C",
        "&#060",
    ];

    # >
    const RIGHT = [
        ">",
        "&gt;",
        "%3E",
        "%25",
        "%253E",
        "&#062",
    ];

    # '
    const QUOTE = [
        "'",
        "&apos;",
        "%27",
        "&#39",
        "&#039",
    ];

    # "
    const DBLQUOTE = [
        '"',
        "&quot;",
        "%22",
        "&#34;",
        "&#034;",
    ];

    /** @var string */
    private $_sString = '';

    /** @var array */
    private $_XssList = [];

    /** @var bool */
    private $_bXss = false;

    /**
     * DETECT XSS URL ATTACK
     */
    private function _detect() {

        # Init
        $this->_bXss = false;

        # No data
        if(!$this->_sString) { return; }

        # Detect
        foreach ($this->_XssList as $sItem) {
            if(strpos($this->_sString, $sItem) !== false) {
                $this->_bXss = true;
            }
        }

    }

    /**
     * Xss constructor.
     * @param string $sString
     */
    public function __construct($sString = '') {
        $this->_XssList = array_merge(self::LEFT, self::RIGHT, self::QUOTE, self::DBLQUOTE);
        $this->setUrl($sString);
    }

    /**
     * @param string $sString
     * @return $this
     */
    public function setUrl($sString) {
        $this->_sString = (string) $sString;
        $this->_detect();
        return $this;
    }

    /**
     * @return string
     */
    public function getFiltered() {
        return htmlspecialchars($this->_sString, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * @return string
     */
    public function getOriginal() {
        return $this->_sString;
    }

    /**
     * @return bool
     */
    public function isXss() {
        return $this->_bXss;
    }

}