<?php

namespace Sandstorm\NeosAcl\Security;

use Neos\ContentRepository\Core\CommandHandler\CommandInterface;
use Neos\ContentRepository\Core\Feature\Security\AuthProviderInterface;
use Neos\ContentRepository\Core\Feature\Security\Dto\Privilege;
use Neos\ContentRepository\Core\Feature\Security\Dto\UserId;
use Neos\ContentRepository\Core\Projection\ContentGraph\ContentGraphReadModelInterface;
use Neos\ContentRepository\Core\Projection\ContentGraph\VisibilityConstraints;
use Neos\ContentRepository\Core\SharedModel\ContentRepository\ContentRepositoryId;
use Neos\ContentRepository\Core\SharedModel\Workspace\WorkspaceName;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Neos\Domain\Service\UserService;
use Neos\Neos\Domain\SubtreeTagging\NeosVisibilityConstraints;
use Neos\Neos\Security\Authorization\ContentRepositoryAuthorizationService;
use Neos\Neos\Security\Authorization\Privilege\ReadNodePrivilege;
use Neos\Neos\Security\Authorization\Privilege\SubtreeTagPrivilegeSubject;
use Neos\Neos\Security\ContentRepositoryAuthProvider\ContentRepositoryAuthProvider;
use Sandstorm\NeosAcl\Domain\Model\DynamicRole;
use Sandstorm\NeosAcl\Domain\Repository\DynamicRoleRepository;

class ACLAuthProvider implements AuthProviderInterface {
    private ContentRepositoryAuthProvider $contentRepositoryAuthProvider;

    #[Inject]
    protected DynamicRoleRepository $dynamicRoleRepository;

    public function __construct(
        private ContentRepositoryId $contentRepositoryId,
        private UserService $userService,
        private ContentGraphReadModelInterface $contentGraphReadModel,
        private ContentRepositoryAuthorizationService $authorizationService,
        private SecurityContext $securityContext,
    ) {
        $this->contentRepositoryAuthProvider = new ContentRepositoryAuthProvider($this->contentRepositoryId, $this->userService, $this->contentGraphReadModel, $this->authorizationService, $this->securityContext);
    }

    public function getAuthenticatedUserId(): ?UserId {
        return $this->contentRepositoryAuthProvider->getAuthenticatedUserId();
    }

    public function canReadNodesFromWorkspace(WorkspaceName $workspaceName): Privilege {
        $roles = $this->securityContext->getRoles();
        foreach ($roles as $role) {
            $identifier = $role->getIdentifier();
            if (!str_starts_with($identifier, 'Dynamic:')) {
                continue;
            }
            $parts = explode('Dynamic:', $identifier);
            $name = $parts[1];
            /** @var DynamicRole $dynamicRole */
            $dynamicRole = $this->dynamicRoleRepository->findByName($name);

            if(in_array($workspaceName->value, $dynamicRole->getWorkspaceNames())){
                return Privilege::granted("");
            }

        }

        return $this->contentRepositoryAuthProvider->canReadNodesFromWorkspace($workspaceName);

    }

    public function getVisibilityConstraints(WorkspaceName $workspaceName): VisibilityConstraints {
        $restrictedSubtreeTags = NeosVisibilityConstraints::excludeRemoved()->excludedSubtreeTags;
        /** @var ReadNodePrivilege $privilege */
        foreach ($this->policyService->getAllPrivilegesByType(ReadNodePrivilege::class) as $privilege) {
            if (!$this->privilegeManager->isGrantedForRoles($roles, ReadNodePrivilege::class, new SubtreeTagPrivilegeSubject($privilege->getSubtreeTags(), $contentRepositoryId))) {
                $restrictedSubtreeTags = $restrictedSubtreeTags->merge($privilege->getSubtreeTags());
            }
        }
        return VisibilityConstraints::excludeSubtreeTags($restrictedSubtreeTags);
    }

    public function canExecuteCommand(CommandInterface $command): Privilege {
        // TODO: Implement canExecuteCommand() method.
    }
}
