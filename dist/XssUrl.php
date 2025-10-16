<?php
namespace Coercive\Security\Xss;

/**
 * XSS URL
 *
 * @package oercive\Security\Xss
 * @link https://github.com/Coercive/Xss
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright 2025 Anthony Moral
 * @license MIT
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
		"%0*28",
		"&#0*40",
		"&#x0*28",
	];

	# )
	const RIGHT_BRACKET = [
		'\)',
		"%0*29",
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
	private string $url = '';

	/** @var array Blacklist merged items */
	private array $list;

	/** @var bool Is Xss detected */
	private bool $xss = false;

	/**
	 * Detect xss url attack
	 *
	 * @return void
	 */
	private function detect(): void
	{
		$this->xss = false;
		if($this->url) {
			foreach ($this->list as $item) {
				if(preg_match("`$item`i", $this->url)) {
					$this->xss = true;
				}
			}
		}
	}

	/**
	 * Xss constructor.
	 *
	 * @return void
	 */
	public function __construct()
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
	}

	/**
	 * Include custom characters in detection list
	 *
	 * @param array $characters
	 * @return XssUrl
	 */
	public function include(array $characters): XssUrl
	{
		$this->list = array_merge($this->list, $characters);
		return $this;
	}

	/**
	 * Exclude custom characters from detection list
	 *
	 * @param array $characters
	 * @return XssUrl
	 */
	public function exclude(array $characters): XssUrl
	{
		$this->list = array_diff($this->list, $characters);
		return $this;
	}

	/**
	 * Set url for xss detection
	 *
	 * @param string $url [optional]
	 * @return $this
	 */
	public function setUrl(string $url = ''): XssUrl
	{
		$this->url = $url;
		$this->detect();
		return $this;
	}

	/**
	 * Get the filtered url
	 * (remove unallowed characters)
	 *
	 * @param string $replacement [optional]
	 * @return string
	 */
	public function getFiltered(string $replacement = ''): string
	{
		$filtered = $this->url;
		foreach ($this->list as $item) {
			$filtered = preg_replace("`$item`i", $replacement, $filtered);
		}
		return $filtered;
	}

	/**
	 * @return string
	 */
	public function getSource(): string
	{
		return $this->url;
	}

	/**
	 * @return bool
	 */
	public function isXss(): bool
	{
		return $this->xss;
	}
}