/**
 * 定义程序中使用的所有时间相关常量。
 */
export const SCRIPT_CONSTANTS = {
  /**
   * [仅用于 Cookie] 短期会话的有效期，单位：秒。
   * 用户未勾选“记住我”时使用。
   */
  COOKIE_LIFETIME_SHORT_SECONDS: 8 * 60 * 60, // 8 小时

  /**
   * [仅用于 Cookie] 长期会话的有效期，单位：秒。
   * 用户勾选了“记住我”时使用。
   */
  COOKIE_LIFETIME_LONG_SECONDS: 30 * 24 * 60 * 60, // 30 天

  /**
   * [仅用于 Token] 伪造 token 的“假象”有效期，单位：秒。
   * 设置一个足够大的值，以防止前端触发任何自动刷新或过期逻辑。
   */
  FAKE_TOKEN_LIFETIME_SECONDS: 365 * 24 * 60 * 60, // 1 年
};

/**
 * 定义需要使用用户自身凭证进行操作的特殊 API 路径。
 * 所有以此处定义的字符串开头的路径都会被视为“特殊请求”。
 */
export const SPECIAL_API_PATHS = [
//   '/api/submission',
  // 您可以在此添加其他需要用户身份的路径
];