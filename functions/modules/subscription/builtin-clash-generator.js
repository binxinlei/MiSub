/**
 * 内置 Clash 配置生成器
 * 不依赖外部 subconverter，直接将节点 URL 转换为完整 Clash 配置
 * 支持 dialer-proxy、reality-opts 等特殊参数
 */
import { urlsToClashProxies } from '../../utils/url-to-clash.js';
import { getUniqueName } from './name-utils.js';
import { isMetaCore } from './user-agent-utils.js';
import {
    POLICY_GROUPS,
    RULE_SETS,
    getBuiltinRules,
    getRemoteProviderDefinitions,
    DEFAULT_SELECT_GROUP,
    DEFAULT_RELAY_GROUP,
    pruneProxyGroups
} from './builtin-rules-provider.js';
import yaml from 'js-yaml';

/**
 * 清理字符串中的控制字符（保留换行和制表符）
 * @param {string} str - 输入字符串
 * @returns {string} 清理后的字符串
 */
function cleanControlChars(str) {
    if (typeof str !== 'string') return str;

    // 移除控制字符，但保留换行(\n)、回车(\r)、制表符(\t)
    // eslint-disable-next-line no-control-regex
    return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * 递归清理对象中所有字符串的控制字符
 * @param {any} obj - 输入对象
 * @returns {any} 清理后的对象
 */
function deepCleanControlChars(obj) {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
        return cleanControlChars(obj);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => deepCleanControlChars(item));
    }

    if (typeof obj === 'object') {
        const cleaned = {};

        for (const [key, value] of Object.entries(obj)) {
            cleaned[cleanControlChars(key)] =
                deepCleanControlChars(value);
        }

        return cleaned;
    }

    return obj;
}

/**
 * 处理重名节点，确保每个节点名称唯一
 * @param {Object[]} proxies - 代理对象数组
 */
function deduplicateNames(proxies) {
    const usedNames = new Map();

    proxies.forEach(proxy => {
        proxy.name = getUniqueName(proxy.name, usedNames);
    });
}

/**
 * 移除仅供内部分组使用、不能输出到 Clash/Mihomo 配置的字段。
 * @param {Object[]} proxies
 * @returns {Object[]}
 */
function stripInternalProxyFields(proxies) {
    return proxies.map(proxy => {
        const { metadata, ...publicProxy } = proxy;
        return publicProxy;
    });
}

/**
 * 为 Mihomo/Meta 生成链式代理节点。
 * 当前 Meta 内核不再支持 relay 策略组语义，应通过 dialer-proxy 让落地节点经由入口节点拨号。
 *
 * @param {Object[]} proxies 原始代理对象（保留内部 metadata）
 * @param {Object[]} publicProxies 输出用代理对象（不含内部字段）
 * @param {Object[]} proxyGroups 策略组定义
 * @returns {{proxies: Object[], proxyGroups: Object[]}}
 */
function applyMihomoRelayDialerProxy(
    proxies,
    publicProxies,
    proxyGroups
) {
    const relayGroup = proxyGroups.find(
        group => group.name === '🔗 链式代理'
    );

    if (!relayGroup) {
        return {
            proxies: publicProxies,
            proxyGroups
        };
    }

    const chainProxies = publicProxies.map(proxy => ({
        ...proxy,
        name: `🔗 链式代理 - ${proxy.name}`,
        'dialer-proxy': '入口节点'
    }));

    const chainNames = chainProxies.map(
        proxy => proxy.name
    );

    const nextProxyGroups = proxyGroups
        .map(group => {
            if (group.name === '🔗 链式代理') {
                return {
                    ...group,

                    // Meta/Mihomo 不再使用 relay group。
                    // 保持上一版可用结构：
                    // “链式代理”直接选择带 dialer-proxy 的落地副本。
                    type: 'select',
                    proxies: chainNames
                };
            }

            if (group.name === '落地节点') {
                return null;
            }

            return group;
        })
        .filter(Boolean);

    return {
        proxies: [
            ...publicProxies,
            ...chainProxies
        ],
        proxyGroups: pruneProxyGroups(
            nextProxyGroups,
            [...proxies, ...chainProxies]
        )
    };
}

/**
 * 将单个 Proxy 对象转换成单行 Flow Style YAML。
 *
 * 例如：
 *
 * {
 *   name: xxx,
 *   type: vless,
 *   server: xxx,
 *   xhttp-opts: {
 *     path: xxx,
 *     host: xxx
 *   }
 * }
 *
 * 最终：
 *
 * {name: xxx, type: vless, server: xxx, xhttp-opts: {path: xxx, host: xxx}}
 *
 * @param {Object} proxy
 * @returns {string}
 */
function dumpProxyAsFlowYaml(proxy) {
    if (!proxy || typeof proxy !== 'object') {
        return JSON.stringify(proxy);
    }

    let value = yaml.dump(proxy, {
        flowLevel: 0,
        lineWidth: -1,
        noRefs: true,
        quotingType: '"',
        forceQuotes: false
    }).trim();

    /*
     * js-yaml 在某些情况下即使使用 Flow Style，
     * 仍可能因为内容较长产生换行。
     *
     * 这里把换行压成空格，确保一个 Proxy 只占一行。
     */
    value = value
        .replace(/\r?\n/g, ' ')
        .replace(/[ \t]+/g, ' ')
        .trim();

    return value;
}

/**
 * 专门生成 Clash proxies 部分。
 *
 * 最终格式：
 *
 * proxies:
 *   - {name: xxx, type: vless, server: xxx, xhttp-opts: {path: xxx, host: xxx}}
 *   - {name: xxx, type: trojan, server: xxx, ws-opts: {path: xxx, headers: {Host: xxx}}}
 *
 * @param {Object[]} proxies
 * @returns {string}
 */
function dumpProxiesAsFlowYaml(proxies) {
    if (!Array.isArray(proxies) || proxies.length === 0) {
        return 'proxies: []';
    }

    const lines = proxies.map(proxy => {
        return `  - ${dumpProxyAsFlowYaml(proxy)}`;
    });

    return `proxies:\n${lines.join('\n')}`;
}

/**
 * 生成内置 Clash 配置
 * @param {string} nodeList - 节点列表（换行分隔的 URL）
 * @param {Object} options - 配置选项
 * @returns {string} Clash YAML 配置
 */
export function generateBuiltinClashConfig(
    nodeList,
    options = {}
) {
    const {
        fileName = 'MiSub',
        enableUdp = true,
        enableTfo = false,
        skipCertVerify = false,
        ruleLevel = 'std',
        userAgent = '',
        hiddifyCompatible = false
    } = options;

    const enableMihomoSyntax =
        Boolean(options.isMeta) ||
        isMetaCore(
            userAgent,
            options.searchParams
        );

    const isHiddifyClient =
        hiddifyCompatible ||
        /hiddify/i.test(userAgent || '');

    // 解析节点 URL 列表（先清理控制字符）
    const cleanedNodeList =
        cleanControlChars(nodeList);

    const nodeUrls = cleanedNodeList
        .split('\n')
        .map(line => line.trim())
        .filter(
            line =>
                line &&
                !line.startsWith('#')
        );

    // 转换为 Clash 代理对象
    let proxies = urlsToClashProxies(
        nodeUrls,
        options
    );

    // 清理控制字符
    proxies = deepCleanControlChars(
        proxies
    );

    // 强制跳过证书验证
    // （已在 urlsToClashProxies 中全局处理）

    // 处理重名节点
    deduplicateNames(proxies);

    if (proxies.length === 0) {
        return '# No valid proxies found\nproxies: []\n';
    }

    // 生成 YAML
    try {
        const levelKey =
            (ruleLevel || 'std').toUpperCase();

        const rawRules = isHiddifyClient
            ? ['MATCH,🚀 节点选择']
            : getBuiltinRules(
                  levelKey,
                  'clash'
              );

        // 生成策略组并执行引用修剪
        const policyGroupsFactory =
            POLICY_GROUPS[levelKey] ||
            POLICY_GROUPS.STD;

        let proxyGroups =
            policyGroupsFactory(
                proxies,
                options
            );

        proxyGroups =
            pruneProxyGroups(
                proxyGroups,
                proxies
            );

        /*
         * 提取远程 Provider 定义。
         *
         * Hiddify 4.x 的 Clash 转 sing-box
         * 解析对 rule-providers 兼容性较差，
         * 自动识别为 Hiddify 时降级为纯 MATCH 规则。
         */
        const ruleProviders =
            isHiddifyClient
                ? {}
                : getRemoteProviderDefinitions(
                      'clash',
                      rawRules
                  );

        // 转换规则行为最终字符串
        const clashRules = rawRules
            .map(r => {
                if (typeof r === 'string') {
                    return r;
                }

                if (
                    r.type ===
                    'rule-provider'
                ) {
                    return `RULE-SET,${r.provider},${r.target}`;
                }

                return null;
            })
            .filter(Boolean);

        /*
         * 去掉内部 metadata。
         */
        let publicProxies =
            stripInternalProxyFields(
                proxies
            );

        /*
         * Mihomo Relay / dialer-proxy
         */
        if (
            levelKey === 'RELAY' &&
            enableMihomoSyntax
        ) {
            const relayConfig =
                applyMihomoRelayDialerProxy(
                    proxies,
                    publicProxies,
                    proxyGroups
                );

            publicProxies =
                relayConfig.proxies;

            proxyGroups =
                relayConfig.proxyGroups;
        }

        /*
         * ==========================================================
         * 这里是本次修改最重要的地方
         * ==========================================================
         *
         * 不再：
         *
         *     'proxies': publicProxies
         *
         * 因为 js-yaml 会把 Proxy 输出成：
         *
         *     - name: xxx
         *       type: vless
         *       server: xxx
         *
         * 我们下面会单独生成：
         *
         *     - {name: xxx, type: vless, server: xxx}
         */
        const config = {
            'mixed-port': 7890,
            'allow-lan': true,
            'mode': 'rule',
            'log-level': 'info',
            'external-controller': ':9090',

            'dns': {
                'enable': true,
                'listen': '0.0.0.0:1053',
                'default-nameserver': [
                    '223.5.5.5',
                    '1.1.1.1'
                ],
                'enhanced-mode': 'fake-ip',
                'fake-ip-range':
                    '198.18.0.1/16',
                'fake-ip-filter': [
                    '*.lan',
                    '*.localhost'
                ],
                'nameserver': [
                    'https://dns.alidns.com/dns-query',
                    'https://doh.pub/dns-query'
                ]
            },

            /*
             * 这里必须是 undefined。
             *
             * 这样 yaml.dump() 不会生成原来的
             * 多行 proxies。
             */
            'proxies': undefined,

            'profile': {
                'store-selected': true,
                'subscription-url':
                    options.managedConfigUrl ||
                    ''
            },

            'proxy-groups':
                proxyGroups,

            ...(Object.keys(
                ruleProviders
            ).length
                ? {
                      'rule-providers':
                          ruleProviders
                  }
                : {}),

            'rules':
                clashRules
        };

        /*
         * 先让 js-yaml 正常生成其余 Clash 配置。
         */
        let yamlStr = yaml.dump(
            config,
            {
                indent: 2,
                lineWidth: -1,
                noRefs: true,
                quotingType: '"',
                forceQuotes: false
            }
        );

        /*
         * 单独生成单行 proxies。
         */
        const proxiesYaml =
            dumpProxiesAsFlowYaml(
                publicProxies
            );

        /*
         * 把 proxies 放到 profile 前面。
         *
         * 最终结构：
         *
         * dns:
         *   ...
         *
         * proxies:
         *   - {name: ..., ...}
         *
         * profile:
         *   ...
         *
         * proxy-groups:
         *   ...
         */
        if (/^profile:/m.test(yamlStr)) {
            yamlStr =
                yamlStr.replace(
                    /^profile:/m,
                    `${proxiesYaml}\nprofile:`
                );
        } else {
            /*
             * 理论上正常配置一定有 profile。
             * 如果没有，则直接放在最前面。
             */
            yamlStr =
                `${proxiesYaml}\n${yamlStr}`;
        }

        /*
         * 最终清理，确保输出没有控制字符。
         */
        return cleanControlChars(
            yamlStr
        );

    } catch (e) {
        console.error(
            '[BuiltinClash] Generation failed:',
            e
        );

        /*
         * Fallback：
         * 至少返回包含节点的有效 YAML 结构，
         * 而不是传回会导致 Clash 报错的 Base64。
         */
        const fallbackProxies =
            Array.isArray(proxies)
                ? stripInternalProxyFields(
                      proxies
                  )
                : [];

        const selectGroup =
            (ruleLevel || '')
                .toUpperCase() ===
            'RELAY'
                ? DEFAULT_RELAY_GROUP
                : DEFAULT_SELECT_GROUP;

        const fallbackYaml =
            `proxies:\n${
                fallbackProxies
                    .map(
                        p =>
                            `  - ${dumpProxyAsFlowYaml(
                                p
                            )}`
                    )
                    .join('\n')
            }\n` +
            `proxy-groups:\n` +
            `  - name: ${selectGroup}\n` +
            `    type: select\n` +
            `    proxies: ${JSON.stringify(
                fallbackProxies.map(
                    p => p.name
                )
            )}\n` +
            `rules:\n` +
            `  - MATCH,${selectGroup}\n`;

        return fallbackYaml;
    }
}

/**
 * 仅生成代理列表（不包含完整配置）
 * @param {string} nodeList - 节点列表
 * @returns {string} 仅包含 proxies 部分的 YAML
 */
export function generateProxiesOnly(
    nodeList
) {
    const cleanedNodeList =
        cleanControlChars(nodeList);

    const nodeUrls = cleanedNodeList
        .split('\n')
        .map(line => line.trim())
        .filter(
            line =>
                line &&
                !line.startsWith('#')
        );

    let proxies =
        urlsToClashProxies(
            nodeUrls
        );

    // 清理控制字符
    proxies =
        deepCleanControlChars(
            proxies
        );

    // 处理重名节点
    deduplicateNames(proxies);

    try {
        const publicProxies =
            stripInternalProxyFields(
                proxies
            );

        /*
         * 使用和完整 Clash 配置相同的
         * 单行 Proxy 格式。
         */
        return cleanControlChars(
            dumpProxiesAsFlowYaml(
                publicProxies
            ) + '\n'
        );

    } catch (e) {
        const fallbackProxies =
            Array.isArray(proxies)
                ? stripInternalProxyFields(
                      proxies
                  )
                : [];

        return (
            `proxies:\n` +
            fallbackProxies
                .map(
                    p =>
                        `  - ${dumpProxyAsFlowYaml(
                            p
                        )}`
                )
                .join('\n') +
            '\n'
        );
    }
}
