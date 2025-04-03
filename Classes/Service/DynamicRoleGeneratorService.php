<?php

namespace Sandstorm\NeosAcl\Service;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\Flow\Annotations as Flow;
use Sandstorm\NeosAcl\Domain\Dto\MatcherConfiguration;
use Sandstorm\NeosAcl\Domain\Model\DynamicRole;
use Sandstorm\NeosAcl\DynamicRoleEnforcement\DynamicPolicyRegistry;

/**
 * @Flow\Scope("singleton")
 */
class DynamicRoleGeneratorService
{

    /**
     * @Flow\Inject
     * @var \Doctrine\ORM\EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @Flow\Inject(lazy=false)
     * @var DynamicPolicyRegistry
     */
    protected $dynamicPolicyRegistry;

    public function onConfigurationLoaded(&$configuration)
    {
        // NOTE: this hook seems to be only triggered in runtime; not in compiletime (which is great for us!)

        $customConfiguration = [];
        $connection = $this->entityManager->getConnection();
        $rows = $connection->executeQuery('SELECT name, abstract, parentrolenames, matcher, privilege FROM sandstorm_neosacl_domain_model_dynamicrole')->fetchAll();
        foreach ($rows as $row) {

            $matcherConfig = json_decode($row['matcher'], true);
            $matcher = MatcherConfiguration::fromJson($matcherConfig)->toPolicyMatcherString();
            $privileges = [];

            if ($row['privilege'] === DynamicRole::PRIVILEGE_VIEW_EDIT || $row['privilege'] === DynamicRole::PRIVILEGE_VIEW_EDIT_CREATE_DELETE) {
                $customConfiguration['privilegeTargets']['Neos\Neos\Security\Authorization\Privilege\EditNodePrivilege']['Dynamic:' . $row['name'] . '.EditNode'] = [
                    'matcher' => $matcher
                ];

                $privileges[] = [
                    'privilegeTarget' => 'Dynamic:' . $row['name'] . '.EditNode',
                    'permission' => 'GRANT'
                ];
            }

            if ($row['privilege'] === DynamicRole::PRIVILEGE_VIEW_EDIT_CREATE_DELETE) {
                $customConfiguration['privilegeTargets']['Neos\Neos\Security\Authorization\Privilege\EditNodePrivilege']['Dynamic:' . $row['name'] . '.CreateNode'] = [
                    'matcher' => $matcher
                ];
                $customConfiguration['privilegeTargets']['Neos\Neos\Security\Authorization\Privilege\EditNodePrivilege']['Dynamic:' . $row['name'] . '.RemoveNode'] = [
                    'matcher' => $matcher
                ];

                $privileges[] = [
                    'privilegeTarget' => 'Dynamic:' . $row['name'] . '.CreateNode',
                    'permission' => 'GRANT'
                ];
                $privileges[] = [
                    'privilegeTarget' => 'Dynamic:' . $row['name'] . '.RemoveNode',
                    'permission' => 'GRANT'
                ];
            }

            $customConfiguration['roles']['Dynamic:' . $row['name']] = [
                'abstract' => intval($row['abstract']) === 1,
                'parentRoles' => json_decode($row['parentrolenames'], true),
                'privileges' => $privileges
            ];
        }

        $this->dynamicPolicyRegistry->registerDynamicPolicyAndMergeThemWithOriginal($customConfiguration, $configuration);
    }
}
