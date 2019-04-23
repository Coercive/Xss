<?php
namespace Coercive\Security\Xss;

/**
 * XSS URL
 *
 * @package		Coercive\Security\Xss
 * @link		https://github.com/Coercive/Xss
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2019 Anthony Moral
 * @license 	MIT
 */
class XssUrl
{
	# <
	const LESS_THAN = [
		"<",
		"&lt",
		"%0*3C",
		"%0*25",
		"%0*253C",
		"&#0*60",
		"&#x0*3c",
	];

	# >
	const GREATHER_THAN = [
		">",
		"&gt",
		"%0*3E",
		"%0*25",
		"%0*253E",
		"&#0*62",
		"&#x0*3e",
	];

	# '
	const QUOTE = [
		"'",
		"&apos",
		"%0*27",
		"&#0*39",
		"&#x0*27",
	];

	# "
	const DBLQUOTE = [
		'"',
		"&quot",
		"%0*22",
		"&#0*34",
		"&#x0*22",
	];

	# (
	const LEFT_BRACKET = [
		'\(',
		"&#0*40",
		"&#x0*28",
	];

	# )
	const RIGHT_BRACKET = [
		'\)',
		"&#0*41",
		"&#x0*29",
	];

	# ;
	const SEMICOLON = [
		'\;',
		"&#0*59",
		"&#x0*3b",
	];

	/** @var string Given url */
	private $string = '';

	/** @var string|null Filtered url */
	private $filtered = null;

	/** @var array Blacklist merged items */
	private $list = [];

	/** @var bool Is Xss detected */
	private $xss = false;

	/**
	 * DETECT XSS URL ATTACK
	 *
	 * @return void
	 */
	private function detect()
	{
		# Init
		$this->xss = false;

		# No data
		if(!$this->string) { return; }

		# Detect
		foreach ($this->list as $item) {
			if(preg_match("`$item`i", $this->string)) {
				$this->xss = true;
			}
		}
	}

	/**
	 * Xss constructor.
	 *
	 * @param string $string
	 * @return void
	 */
	public function __construct(string $string = '')
	{
		$this->list = array_merge(
			self::LESS_THAN,
			self::GREATHER_THAN,
			self::QUOTE,
			self::DBLQUOTE,
			self::LEFT_BRACKET,
			self::RIGHT_BRACKET,
			self::SEMICOLON
		);
		$this->setUrl($string);
	}

	/**
	 * @param string $string
	 * @return $this
	 */
	public function setUrl(string $string): XssUrl
	{
		$this->string = $string;
		$this->filtered = null;
		$this->detect();
		return $this;
	}

	/**
	 * @return string
	 */
	public function getFiltered(): string
	{
		# Single filtering
		if(null !== $this->filtered) { return $this->filtered; }

		# Clear
		$this->filtered = $this->string;
		foreach ($this->list as $item) {
			$this->filtered = preg_replace("`$item`i", '', $this->filtered);
		}
		return $this->filtered;
	}

	/**
	 * @return string
	 */
	public function getOriginal(): string
	{
		return $this->string;
	}

	/**
	 * @return bool
	 */
	public function isXss(): bool
	{
		return $this->xss;
	}
}
