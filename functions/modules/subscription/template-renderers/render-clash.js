import yaml from 'js-yaml';
import { clashFix } from '../../../utils/format-utils.js';
import { normalizeUnifiedTemplateModel } from '../template-model.js';

function mapGroupType(type) {
    const normalized = String(type || '').trim().toLowerCase();

    if (
        normalized === 'url-test' ||
        normalized === 'fallback' ||
        normalized === 'load-balance' ||
        normalized === 'select'
    ) {
        return normalized;
    }

    return 'select';
}

function filterAutoSelectMembers(group) {
    const type = mapGroupType(group.type);
    const members = Array.isArray(group.members)
        ? group.members.filter(Boolean)
        : [];

    if (!['url-test', 'fallback', 'load-balance'].includes(type)) {
        return members;
    }

    return members.filter(
        member =>
            !['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'].includes(
                String(member).toUpperCase()
            )
    );
}

const ACL4SSR_ROOT_PROVIDER_FILES = new Set([
    'apple',
    'banad',
    'baneasylist',
    'baneasylistchina',
    'baneasyprivacy',
    'banprogramad',
    'chinacompanyip',
    'chinadomain',
    'chinaip',
    'chinaipv6',
    'chinamedia',
    'download',
    'localareanetwork',
    'mjj',
    'proxylite',
    'proxygfwlist',
    'proxymedia',
    'unban'
]);

const ACL4SSR_IPCIDR_PROVIDER_FILES = new Set([
    'amazonip',
    'chinacompanyip',
    'chinaip',
    'chinaipv6',
    'netflixip'
]);

const ACL4SSR_ROOT_LIST_ONLY_FILES = new Set([
    'localareanetwork',
    'banad',
    'banprogramad',
    'chinamedia',
    'proxymedia',
    'chinadomain',
    'download',
    'unban'
]);

function toClashRuleProviderUrl(sourceUrl) {
    if (!/^https?:\/\//i.test(String(sourceUrl || ''))) {
        return sourceUrl;
    }

    try {
        const url = new URL(sourceUrl);

        if (!/raw\.githubusercontent\.com$/i.test(url.hostname)) {
            return sourceUrl;
        }

        const pathParts = url.pathname.split('/').filter(Boolean);
        const owner = pathParts[0] || '';
        const repo = pathParts[1] || '';

        if (
            owner.toLowerCase() !== 'acl4ssr' ||
            repo.toLowerCase() !== 'acl4ssr'
        ) {
            return sourceUrl;
        }

        if (!/\/Clash\/.*\.(list|txt)$/i.test(url.pathname)) {
            return sourceUrl;
        }

        const fileName =
            url.pathname
                .split('/')
                .pop()
                ?.replace(/\.(list|txt)$/i, '') || '';

        if (
            /\/Clash\/[^/]+\.(list|txt)$/i.test(url.pathname) &&
            ACL4SSR_ROOT_LIST_ONLY_FILES.has(fileName.toLowerCase())
        ) {
            return sourceUrl;
        }

        if (/\/Clash\/Ruleset\//i.test(url.pathname)) {
            url.pathname = url.pathname
                .replace(
                    /\/Clash\/Ruleset\//i,
                    '/Clash/Providers/Ruleset/'
                )
                .replace(/\.(list|txt)$/i, '.yaml');
        } else if (
            ACL4SSR_ROOT_PROVIDER_FILES.has(fileName.toLowerCase())
        ) {
            url.pathname = url.pathname
                .replace(/\/Clash\//i, '/Clash/Providers/')
                .replace(/\.(list|txt)$/i, '.yaml');
        } else {
            url.pathname = url.pathname
                .replace(
                    /\/Clash\//i,
                    '/Clash/Providers/Ruleset/'
                )
                .replace(/\.(list|txt)$/i, '.yaml');
        }

        return url.toString();
    } catch {
        return sourceUrl;
    }
}

function getRuleProviderBehavior(providerUrl) {
    try {
        const fileName =
            new URL(providerUrl)
                .pathname
                .split('/')
                .pop()
                ?.replace(/\.(yaml|yml|list|txt|conf)$/i, '') || '';

        if (
            ACL4SSR_IPCIDR_PROVIDER_FILES.has(
                fileName.toLowerCase()
            )
        ) {
            return 'ipcidr';
        }
    } catch {
        // ignore invalid provider url
    }

    return 'classical';
}

function mapRule(rule, ruleProviderMap) {
    const type = String(rule.type || '').toUpperCase();

    if (!type) {
        return null;
    }

    if (type === 'MATCH' || type === 'FINAL') {
        return `MATCH,${rule.policy}`;
    }

    if (type === 'GEOIP') {
        return `GEOIP,${rule.value || 'CN'},${rule.policy}`;
    }

    if (type === 'RULE-SET') {
        const providerName = ruleProviderMap.get(rule.value);

        return `RULE-SET,${providerName || rule.value},${rule.policy}`;
    }

    return `${type},${rule.value},${rule.policy}`;
}


/**
 * 将 JS 值转换成安全的 YAML Flow Scalar。
 *
 * 所有字符串统一使用 JSON 双引号。
 *
 * 这样可以避免：
 *
 * {path: /proxyip=126.121.88.244:14496}
 *
 * 这类 Flow YAML 在部分 YAML 解析器中出现：
 *
 * yaml: line xx: did not find expected ',' or '}'
 */
function flowScalar(value) {
    if (value === null) {
        return 'null';
    }

    if (typeof value === 'string') {
        return JSON.stringify(value);
    }

    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }

    if (typeof value === 'number') {
        if (Number.isFinite(value)) {
            return String(value);
        }

        return 'null';
    }

    return JSON.stringify(value);
}


/**
 * 将 JS 对象安全转换成 YAML Flow Map。
 *
 * 例如：
 *
 * {
 *     name: 'JP-CF电信-家宽',
 *     type: 'vless',
 *     server: '172.64.229.195',
 *     xhttp-opts: {
 *         path: '/proxyip=jp.william.us.ci'
 *     }
 * }
 *
 * 输出：
 *
 * {
 *     "name": "JP-CF电信-家宽",
 *     "type": "vless",
 *     "server": "172.64.229.195",
 *     "xhttp-opts": {
 *         "path": "/proxyip=jp.william.us.ci"
 *     }
 * }
 */
function objectToFlowYaml(value) {
    if (value === null) {
        return 'null';
    }

    if (typeof value !== 'object') {
        return flowScalar(value);
    }

    if (Array.isArray(value)) {
        return `[${value
            .map(item => objectToFlowYaml(item))
            .join(', ')}]`;
    }

    const entries = Object.entries(value);

    const pairs = entries.map(([key, val]) => {
        return `${JSON.stringify(key)}: ${objectToFlowYaml(val)}`;
    });

    return `{${pairs.join(', ')}}`;
}


/**
 * 专门生成 Clash proxies 部分。
 *
 * 输出格式：
 *
 * proxies:
 *   - {"name": "...", "type": "vless", ...}
 *
 * metadata 不输出。
 */
function dumpProxiesAsFlowYaml(proxies) {
    if (!Array.isArray(proxies) || proxies.length === 0) {
        return 'proxies: []';
    }

    const lines = proxies.map(proxy => {
        if (!proxy || typeof proxy !== 'object') {
            return `  - ${flowScalar(proxy)}`;
        }

        // MiSub 内部 metadata 不输出到 Clash 节点
        const { metadata, ...publicProxy } = proxy;

        return `  - ${objectToFlowYaml(publicProxy)}`;
    });

    return `proxies:\n${lines.join('\n')}`;
}


/**
 * 生成完整 Clash YAML。
 *
 * 重点：
 *
 * 1. proxies 不使用 yaml.dump
 * 2. proxies 使用安全的 Flow YAML
 * 3. proxies 放回原来正常的位置
 * 4. 默认顺序保持：
 *
 *    mixed-port
 *    allow-lan
 *    mode
 *    log-level
 *    external-controller
 *    dns
 *    proxies
 *    proxy-groups
 *    rule-providers
 *    rules
 *    profile
 */
function dumpClashConfig(config) {
    const {
        proxies,
        ...restConfig
    } = config;

    /*
     * 找到 proxy-groups 在配置中的位置。
     *
     * 我们要把 proxies 插入到 proxy-groups 之前，
     * 而不是把 proxies 追加到 YAML 最后。
     */
    const entries = Object.entries(restConfig);

    const proxyGroupsIndex = entries.findIndex(
        ([key]) => key === 'proxy-groups'
    );

    /*
     * 理论上 proxy-groups 一定存在。
     *
     * 如果不存在，则退化成：
     *
     * 其他配置
     * proxies
     */
    if (proxyGroupsIndex === -1) {
        const restYaml = yaml.dump(restConfig, {
            indent: 2,
            lineWidth: -1,
            noRefs: true,
            quotingType: '"',
            forceQuotes: false
        });

        const proxyYaml =
            dumpProxiesAsFlowYaml(proxies);

        return `${restYaml}${proxyYaml}\n`;
    }

    /*
     * proxy-groups 之前的配置。
     *
     * 例如：
     *
     * mixed-port
     * allow-lan
     * mode
     * log-level
     * external-controller
     * dns
     */
    const beforeProxyGroups = Object.fromEntries(
        entries.slice(0, proxyGroupsIndex)
    );

    /*
     * proxy-groups 以及后面的配置。
     */
    const afterProxyGroups = Object.fromEntries(
        entries.slice(proxyGroupsIndex)
    );

    /*
     * 第一部分正常使用 js-yaml。
     */
    const beforeYaml = yaml.dump(
        beforeProxyGroups,
        {
            indent: 2,
            lineWidth: -1,
            noRefs: true,
            quotingType: '"',
            forceQuotes: false
        }
    ).trimEnd();

    /*
     * proxies 使用我们自己的安全 Flow YAML。
     */
    const proxyYaml =
        dumpProxiesAsFlowYaml(proxies);

    /*
     * proxy-groups 以及后面的内容继续交给 js-yaml。
     */
    const afterYaml = yaml.dump(
        afterProxyGroups,
        {
            indent: 2,
            lineWidth: -1,
            noRefs: true,
            quotingType: '"',
            forceQuotes: false
        }
    ).trimEnd();

    /*
     * 最终顺序：
     *
     * before
     * ↓
     * proxies
     * ↓
     * proxy-groups
     * ↓
     * rule-providers
     * ↓
     * rules
     * ↓
     * profile
     */
    return [
        beforeYaml,
        proxyYaml,
        afterYaml
    ]
        .filter(Boolean)
        .join('\n') + '\n';
}


export function renderClashFromTemplateModel(model) {
    const normalizedModel =
        normalizeUnifiedTemplateModel(model);

    const ruleProviders = {};
    const ruleProviderMap = new Map();
    let providerCounter = 0;

    normalizedModel.rules.forEach(rule => {
        const type =
            String(rule.type || '').toUpperCase();

        if (
            type !== 'RULE-SET' ||
            !rule.value ||
            !/^https?:\/\//i.test(rule.value)
        ) {
            return;
        }

        const providerUrl =
            toClashRuleProviderUrl(rule.value);

        if (ruleProviderMap.has(providerUrl)) {
            return;
        }

        let nameHint = 'rs';

        try {
            const urlPath =
                new URL(providerUrl).pathname;

            const fileName =
                urlPath
                    .split('/')
                    .pop()
                    ?.replace(
                        /\.(yaml|yml|list|txt|conf)$/i,
                        ''
                    ) || '';

            if (fileName) {
                nameHint = fileName
                    .replace(/[^a-zA-Z0-9]/g, '_')
                    .toLowerCase();
            }
        } catch {
            // ignore invalid provider url
        }

        const providerName =
            `${nameHint}_${providerCounter++}`;

        ruleProviderMap.set(
            providerUrl,
            providerName
        );

        const usesTextList =
            /\.(list|txt)$/i.test(providerUrl);

        ruleProviders[providerName] = {
            type: 'http',
            behavior:
                getRuleProviderBehavior(providerUrl),
            url: providerUrl,
            path:
                `./ruleset/${providerName}.${usesTextList ? 'list' : 'yaml'}`,
            interval: 86400,
            ...(usesTextList
                ? { format: 'text' }
                : {})
        };
    });


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
         * proxies 保持在这里。
         *
         * dumpClashConfig() 会把它实际输出到
         * proxy-groups 之前。
         */
        'proxies':
            normalizedModel.proxies,

        'proxy-groups':
            normalizedModel.groups
                .filter(group =>
                    (
                        Array.isArray(group.members) &&
                        group.members.length > 0
                    ) ||
                    (
                        Array.isArray(group.filters) &&
                        group.filters.length > 0
                    )
                )
                .map(group => {
                    return {
                        name: group.name,

                        type:
                            mapGroupType(group.type),

                        proxies:
                            filterAutoSelectMembers(group),

                        filter:
                            Array.isArray(group.filters) &&
                            group.filters.length > 0
                                ? group.filters.join('|')
                                : undefined,

                        ...group.options
                    };
                }),

        'rule-providers':
            Object.keys(ruleProviders).length > 0
                ? ruleProviders
                : undefined,

        'rules':
            normalizedModel.rules
                .map(rule => {
                    if (
                        String(rule.type || '').toUpperCase() !==
                            'RULE-SET' ||
                        !rule.value
                    ) {
                        return mapRule(
                            rule,
                            ruleProviderMap
                        );
                    }

                    return mapRule(
                        {
                            ...rule,
                            value:
                                toClashRuleProviderUrl(
                                    rule.value
                                )
                        },
                        ruleProviderMap
                    );
                })
                .filter(Boolean),

        'profile': {
            'store-selected': true,

            'subscription-url':
                normalizedModel.settings
                    .managedConfigUrl || ''
        }
    };


    let yamlStr =
        dumpClashConfig(config);

    /*
     * 保留项目原来的 Clash 修正逻辑。
     */
    yamlStr = clashFix(yamlStr);

    return yamlStr;
}
