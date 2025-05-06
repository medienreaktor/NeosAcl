<?php

namespace Sandstorm\NeosAcl\Service;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\Flow\Annotations as Flow;
use Sandstorm\NeosAcl\Domain\Model\DynamicRole;
use Sandstorm\NeosAcl\Domain\Repository\DynamicRoleRepository;
use Sandstorm\NeosAcl\DynamicRoleEnforcement\DynamicPolicyRegistry;

/**
 * @Flow\Scope("singleton")
 */
class DynamicRoleGeneratorService {

    /**
     * @Flow\Inject
     * @var DynamicRoleRepository
     */
    protected $dynamicRoleRepository;

    /**
     * @Flow\Inject(lazy=false)
     * @var DynamicPolicyRegistry
     */
    protected $dynamicPolicyRegistry;

    public function onConfigurationLoaded(&$configuration) {
        $customConfiguration = [];

        $dynamicRoles = $this->dynamicRoleRepository->findAll();
        /** @var DynamicRole $dynamicRole */
        foreach ($dynamicRoles as $dynamicRole) {
            $privileges = [];

            $customConfiguration['roles']['Dynamic:' . $dynamicRole->getName()] = [
                'abstract' => $dynamicRole->getAbstract(),
                'parentRoles' => json_decode($dynamicRole->getParentRoleNames(), true)
            ];
        }

        $this->dynamicPolicyRegistry->registerDynamicPolicyAndMergeThemWithOriginal($customConfiguration, $configuration);
    }
}
