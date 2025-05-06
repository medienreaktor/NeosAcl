<?php

namespace Sandstorm\NeosAcl\Domain\Model;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\Flow\Annotations as Flow;
use Doctrine\ORM\Mapping as ORM;
use Sandstorm\NeosAcl\Domain\Dto\MatcherConfiguration;
use Sandstorm\NeosAcl\Domain\Dto\DynamicRoleSelectedDimensionPreset;
use Sandstorm\NeosAcl\Domain\Dto\DynamicRoleSelectedNode;

/**
 * @Flow\Entity
 */
class DynamicRole {

    /**
     * @Flow\Validate(type="RegularExpression", options={"regularExpression"="/^\w+$/"})
     * @var string
     */
    protected $name;

    /**
     * @var boolean
     */
    protected $abstract;

    /**
     * @ORM\Column(type="flow_json_array")
     * @var array<string>
     */
    protected $parentRoleNames;


    /**
     * @ORM\Column(type="flow_json_array")
     * @var array<string>
     */
    protected $workspaceNames;

    /**
     * @var DynamicRoleSelectedNode[]
     */
    protected $selectedNodes;

    /**
     * @var DynamicRoleSelectedDimensionPreset[]
     */
    protected $selectedDimensionPresets;

    const PRIVILEGE_VIEW = 'view';
    const PRIVILEGE_VIEW_EDIT = 'view_edit';
    const PRIVILEGE_VIEW_EDIT_CREATE_DELETE = 'view_edit_create_delete';

    /**
     * @var string
     */
    protected $privilege = self::PRIVILEGE_VIEW;

    /**
     * @return string
     */
    public function getName() {
        return $this->name;
    }

    /**
     * @param string $name
     */
    public function setName($name) {
        $this->name = $name;
    }

    /**
     * @return boolean
     */
    public function getAbstract() {
        return $this->abstract;
    }

    /**
     * @param boolean $abstract
     */
    public function setAbstract($abstract) {
        $this->abstract = $abstract;
    }

    /**
     * @return array
     */
    public function getParentRoleNames() {
        return $this->parentRoleNames;
    }

    /**
     * @param array $parentRoleNames
     */
    public function setParentRoleNames($parentRoleNames) {
        $this->parentRoleNames = $parentRoleNames;
    }

    /**
     * @return string
     */
    public function getPrivilege() {
        return $this->privilege;
    }

    /**
     * @param string $privilege
     */
    public function setPrivilege($privilege) {
        $this->privilege = $privilege;
    }


    public function getPrivilegeExplanation(): string {
        switch ($this->privilege) {
            case self::PRIVILEGE_VIEW_EDIT:
                return 'view, edit';
            case self::PRIVILEGE_VIEW_EDIT_CREATE_DELETE:
                return 'view, edit, create, delete';
            default:
                return 'view';
        }
    }

    /**
     * @return string[]
     */
    public function getWorkspaceNames(): array {
        return $this->workspaceNames;
    }

    /**
     * @return DynamicRoleSelectedDimensionPreset[]
     */
    public function getSelectedDimensionPresets(): array {
        return $this->selectedDimensionPresets;
    }

    /**
     * @return DynamicRoleSelectedNode[]
     */
    public function getSelectedNodes(): array {
        return $this->selectedNodes;
    }

    /**
     * @param string[] $workspaceNames
     */
    public function setWorkspaceNames(array $workspaceNames): void {
        $this->workspaceNames = $workspaceNames;
    }

    /**
     * @param DynamicRoleSelectedDimensionPreset[] $selectedDimensionPresets
     */
    public function setSelectedDimensionPresets(array $selectedDimensionPresets): void {
        $this->selectedDimensionPresets = $selectedDimensionPresets;
    }

    /**
     * @param DynamicRoleSelectedNode[] $selectedNodes
     */
    public function setSelectedNodes(array $selectedNodes): void {
        $this->selectedNodes = $selectedNodes;
    }

}
