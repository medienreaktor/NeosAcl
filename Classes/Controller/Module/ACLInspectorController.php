<?php
namespace Sandstorm\NeosAcl\Controller\Module;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\ContentRepository\Core\Projection\ContentGraph\Node;
use Neos\ContentRepositoryRegistry\ContentRepositoryRegistry;
use Neos\Eel\FlowQuery\FlowQuery;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Fusion\View\FusionView;
use Neos\Neos\Controller\Module\AbstractModuleController;
use Neos\Neos\FrontendRouting\SiteDetection\SiteDetectionResult;
use Sandstorm\NeosAcl\Dto\ACLCheckerDto;
use Sandstorm\NeosAcl\Service\ACLCheckerService;

class ACLInspectorController extends AbstractModuleController
{

    protected $defaultViewObjectName = FusionView::class;


    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var ACLCheckerService
     */
    protected $aclCheckService;

    /**
     * @Flow\Inject
     * @var ContentRepositoryRegistry
     */
    protected $contentRepositoryRegistry;

    /**
     * @return void
     */
    public function indexAction(ACLCheckerDto $dto = null)
    {
        if ($dto === null) {
            $dto = new ACLCheckerDto();
        }
        $siteDetectionResult = SiteDetectionResult::fromRequest($this->request->getHttpRequest());
        $contentRepositoryId = $siteDetectionResult->contentRepositoryId;

        $nodes = $this->aclCheckService->resolveDto($dto, $contentRepositoryId);

        $this->view->assignMultiple(
            [
                'dto' => $dto,
                'nodes' => $nodes,
                'roles' => $this->policyService->getRoles()
            ]
        );
    }

    /**
     * @param Node $node
     */
    public function showAction(Node $node)
    {
        $roles = $this->policyService->getRoles(true);

        $this->view->assignMultiple([
                'acl' => $this->aclCheckService->checkNodeForRoles($node, $roles),
                'targets' => $this->aclCheckService->checkPrivilegeTargetsForNodeAndRoles($node, $roles),
                'node' => $node,
                'breadcrumbNodes' => $this->breadcrumbNodesForNode($node),
                'childNodes' => $this->aclCheckService->getContentNodes($node, $roles, 999)
        ]);
    }

    /**
     * @param Node $node
     * @return array
     */
    protected function breadcrumbNodesForNode(Node $node)
    {
        $documentNodes = [];
        $flowQuery = new FlowQuery(array($node));
        $nodes = array_reverse($flowQuery->parents('[instanceof Neos.Neos:Document]')->get());
        /** @var Node $node */
        foreach ($nodes as $documentNode) {
            $documentNodes[] = $documentNode;
        }

        $contentRepository = $this->contentRepositoryRegistry->get($node->contentRepositoryId);
        $nodeType = $contentRepository->getNodeTypeManager()->getNodeType($node->nodeTypeName);

        if ($nodeType->isOfType('Neos.Neos:Document')) {
            $documentNodes[] = $node;
        }

        return $documentNodes;
    }
}
